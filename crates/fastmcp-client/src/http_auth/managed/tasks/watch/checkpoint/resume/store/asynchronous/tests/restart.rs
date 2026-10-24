//! Real-file async restart staging, using the parent's reference-only vault.

use super::*;
use crate::http_auth::managed::tasks::watch::checkpoint::resume::client::restart::TaskResumeRestartPolicy;

#[test]
fn reopened_store_stages_all_pages_before_later_mutations() {
    run(|cx| async move {
        let guard = ProcessGenerationGuard::install().unwrap();
        let lane = CredentialIoLane::new(&guard, CredentialIoLimits::default()).unwrap();
        let directory = Directory::new();
        let vault = Vault::default();
        let current = binding("one");
        let mut store = open(&cx, &lane, &directory, vault.clone(), current.clone()).await;
        let mut expected = Vec::new();
        for id in ["PRIVATE / one", "é", "e\u{301}"] {
            let saved = record(&cx, &current, id);
            expected.push(saved.key());
            let (owner, result) = store
                .try_insert(&cx, current.clone(), saved)
                .unwrap()
                .wait(&cx)
                .await
                .unwrap()
                .into_parts();
            result.unwrap();
            store = owner;
        }
        store.close(&cx).unwrap().wait(&cx).await.unwrap();
        let store = open(&cx, &lane, &directory, vault.clone(), current.clone()).await;
        let version = store.revision();
        let bytes = fs::read(directory.0.join("tasks")).unwrap();
        let seals = vault.calls.load(Ordering::SeqCst);
        let (store, staged) = store
            .try_load_restart(&cx, current.clone(), 1, TaskResumeRestartPolicy::default())
            .unwrap()
            .wait(&cx)
            .await
            .unwrap()
            .into_parts();
        let staged = staged.unwrap();
        expected.sort();
        assert_eq!(staged.binding().associated_data(), current.associated_data());
        assert_eq!(staged.plan().len(), 3);
        assert_eq!(staged.plan().charged_records(), 3);
        assert_eq!(
            staged.plan().records().map(TaskResumeRecord::key).collect::<Vec<_>>(),
            expected
        );
        assert_eq!(store.revision(), version);
        assert_eq!(fs::read(directory.0.join("tasks")).unwrap(), bytes);
        assert_eq!(vault.calls.load(Ordering::SeqCst), seals);
        assert!(!format!("{staged:?}").contains("PRIVATE"));
        let first = staged.plan().records().next().unwrap().clone();
        let (store, removed) = store
            .try_remove_expected(&cx, current.clone(), first)
            .unwrap()
            .wait(&cx)
            .await
            .unwrap()
            .into_parts();
        removed.unwrap();
        assert_eq!(staged.plan().len(), 3, "staged controls are independent of source cursors");
        let (store, next) = store
            .try_load_restart(&cx, current, 1, TaskResumeRestartPolicy::default())
            .unwrap()
            .wait(&cx)
            .await
            .unwrap()
            .into_parts();
        assert_eq!(next.unwrap().plan().len(), 2);
        store.close(&cx).unwrap().wait(&cx).await.unwrap();
        lane.begin_shutdown().unwrap();
        lane.wait_drained(&cx, Duration::from_secs(2)).await.unwrap();
    });
}

#[test]
fn failed_staging_returns_unchanged_owner_and_never_exposes_a_prefix() {
    run(|cx| async move {
        let guard = ProcessGenerationGuard::install().unwrap();
        let lane = CredentialIoLane::new(&guard, CredentialIoLimits::default()).unwrap();
        let directory = Directory::new();
        let vault = Vault::default();
        let current = binding("one");
        let mut store = open(&cx, &lane, &directory, vault.clone(), current.clone()).await;
        for id in ["one", "two"] {
            let (owner, result) = store
                .try_insert(&cx, current.clone(), record(&cx, &current, id))
                .unwrap()
                .wait(&cx)
                .await
                .unwrap()
                .into_parts();
            result.unwrap();
            store = owner;
        }
        let before = fs::read(directory.0.join("tasks")).unwrap();
        let version = store.revision();
        let seals = vault.calls.load(Ordering::SeqCst);
        for (owner_binding, page_size, policy, expected) in [
            (current.clone(), 1, TaskResumeRestartPolicy::new(1, 65536, Duration::from_secs(10)).unwrap(), TaskResumeError::Capacity),
            (current.clone(), 1, TaskResumeRestartPolicy::new(8, 64, Duration::from_secs(10)).unwrap(), TaskResumeError::TooLarge),
            (current.clone(), 0, TaskResumeRestartPolicy::default(), TaskResumeError::Capacity),
            (binding("other"), 1, TaskResumeRestartPolicy::default(), TaskResumeError::Unavailable),
        ] {
            let (owner, result) = store
                .try_load_restart(&cx, owner_binding, page_size, policy)
                .unwrap()
                .wait(&cx)
                .await
                .unwrap()
                .into_parts();
            assert!(matches!(result, Err(TaskResumeStoreError::Resume(error)) if error == expected));
            store = owner;
            assert_eq!(store.revision(), version);
            assert_eq!(fs::read(directory.0.join("tasks")).unwrap(), before);
            assert_eq!(vault.calls.load(Ordering::SeqCst), seals);
        }
        let (store, complete) = store
            .try_load_restart(&cx, current, 1, TaskResumeRestartPolicy::default())
            .unwrap()
            .wait(&cx)
            .await
            .unwrap()
            .into_parts();
        assert_eq!(complete.unwrap().plan().len(), 2);
        store.close(&cx).unwrap().wait(&cx).await.unwrap();
        lane.begin_shutdown().unwrap();
        lane.wait_drained(&cx, Duration::from_secs(2)).await.unwrap();
    });
}

#[test]
fn cancelled_staging_wait_retains_the_same_one_use_completion_and_charge() {
    run(|cx| async move {
        let guard = ProcessGenerationGuard::install().unwrap();
        let lane = CredentialIoLane::new(&guard, CredentialIoLimits::default()).unwrap();
        let directory = Directory::new();
        let current = binding("one");
        let store = open(&cx, &lane, &directory, Vault::default(), current.clone()).await;
        let mut staging = store
            .try_load_restart(&cx, current, 1, TaskResumeRestartPolicy::default())
            .unwrap();
        let cancelled = Cx::for_testing();
        cancelled.set_cancel_requested(true);
        assert!(matches!(staging.wait(&cancelled).await, Err(CredentialIoError::WaitCancelled)));
        assert_eq!(lane.snapshot().unwrap().operations, 1);
        let (store, staged) = staging.wait(&cx).await.unwrap().into_parts();
        assert!(staged.unwrap().plan().is_empty());
        assert!(matches!(staging.wait(&cx).await, Err(CredentialIoError::AlreadyReceived)));
        assert!(store.revision().is_none());
        assert!(!directory.0.join("tasks").exists());
        store.close(&cx).unwrap().wait(&cx).await.unwrap();
        lane.begin_shutdown().unwrap();
        lane.wait_drained(&cx, Duration::from_secs(2)).await.unwrap();
        assert_eq!(lane.snapshot().unwrap(), CredentialIoSnapshot::default());
    });
}
