use super::*;

struct Notice;
impl StreamNotification for Notice {}

#[derive(Default)]
struct Decoder { used: (usize, usize) }

impl StreamDecoder<Notice> for Decoder {
    type Terminal = ();

    fn admit(&mut self, frame: &[u8], _: bool)
        -> Result<StreamEvent<(), Notice>, DpopStreamError>
    {
        let event = match frame {
            b"n" => {
                self.used.1 += 1;
                StreamEvent::Notification(Box::new(Notice))
            }
            b"r" => StreamEvent::Result(()),
            _ => return Err(ManagedCoreError::InvalidResponse.into()),
        };
        self.used.0 += frame.len();
        Ok(event)
    }

    fn admit_terminal_tail(&mut self, frame: &[u8]) -> Result<(), DpopStreamError> {
        if frame != b"t" { return Err(ManagedCoreError::InvalidResponse.into()); }
        self.used.0 += 1;
        self.used.1 += 1;
        Ok(())
    }

    fn usage(&self) -> (usize, usize) { self.used }
}

fn limits(events: usize) -> ManagedCoreLimits {
    ManagedCoreLimits::new(8192, 8192, 32768, events,
        std::time::Duration::from_secs(60)).unwrap()
}

#[test]
fn two_decoders_cannot_spend_the_same_last_payload_byte() {
    let budget = SharedStreamBudget::new(limits(3), (32767, 0)).unwrap();
    let mut one = Budgeted::new(Decoder::default(), Some(budget.clone()));
    let mut two = Budgeted::new(Decoder::default(), Some(budget.clone()));
    assert!(matches!(one.admit(b"r", true).unwrap(), StreamEvent::Result(())));
    assert!(two.admit(b"r", true).is_err());
    assert_eq!(two.inner.used, (0, 0), "byte refusal precedes decoding");
    assert_eq!(budget.usage().unwrap(), (32768, 0));
}

#[test]
fn notifications_share_a_cap_but_a_terminal_can_use_remaining_bytes() {
    let budget = SharedStreamBudget::new(limits(1), (0, 0)).unwrap();
    let mut listen = Budgeted::new(Decoder::default(), Some(budget.clone()));
    let mut rpc = Budgeted::new(Decoder::default(), Some(budget.clone()));
    listen.admit(b"n", true).unwrap();
    assert!(rpc.admit(b"n", true).is_err());
    assert_eq!(budget.usage().unwrap(), (1, 1), "refused event spends neither counter");
    // A different, still-live decoder can complete; a refused exchange is not reused.
    let mut final_get = Budgeted::new(Decoder::default(), Some(budget.clone()));
    assert!(matches!(final_get.admit(b"r", true).unwrap(), StreamEvent::Result(())));
    assert_eq!(budget.usage().unwrap(), (2, 1));
}

#[test]
fn malformed_frames_and_tails_do_not_charge_the_shared_ledger() {
    let budget = SharedStreamBudget::new(limits(4), (17, 1)).unwrap();
    let mut decoder = Budgeted::new(Decoder::default(), Some(budget.clone()));
    assert!(decoder.admit(b"bad", true).is_err());
    assert!(decoder.admit_terminal_tail(b"bad").is_err());
    assert_eq!(budget.usage().unwrap(), (17, 1));
}

#[test]
fn complementary_teardown_is_charged_once_alongside_the_other_stream() {
    let budget = SharedStreamBudget::new(limits(2), (9, 0)).unwrap();
    let mut listen = Budgeted::new(Decoder::default(), Some(budget.clone()));
    let mut rpc = Budgeted::new(Decoder::default(), Some(budget.clone()));
    listen.admit(b"n", true).unwrap();
    rpc.admit(b"r", true).unwrap();
    listen.admit(b"r", true).unwrap();
    listen.admit_terminal_tail(b"t").unwrap();
    assert_eq!(budget.usage().unwrap(), (13, 2));
    assert!(listen.admit_terminal_tail(b"t").is_err());
    assert_eq!(budget.usage().unwrap(), (13, 2));
}

#[test]
fn overflow_or_one_exhausted_dimension_cannot_partially_spend_the_other() {
    let budget = SharedStreamBudget::new(limits(2), (100, 2)).unwrap();
    for delta in [(1, 1), (usize::MAX, 0), (0, usize::MAX), (32768, 0)] {
        assert!(budget.charge(delta).is_err());
        assert_eq!(budget.usage().unwrap(), (100, 2));
    }
    assert!(SharedStreamBudget::new(limits(2), (32769, 0)).is_err());
    assert!(SharedStreamBudget::new(limits(2), (0, 3)).is_err());
}

#[test]
fn attaching_an_already_seeded_decoder_does_not_recharge_discovery() {
    let budget = SharedStreamBudget::new(limits(2), (123, 1)).unwrap();
    let mut decoder = Budgeted::new(Decoder { used: (123, 1) }, Some(budget.clone()));
    decoder.admit(b"r", true).unwrap();
    assert_eq!(budget.usage().unwrap(), (124, 1));
    assert_eq!(decoder.usage(), (124, 1));
}

#[test]
fn an_unshared_decoder_preserves_the_original_method_accounting() {
    let mut decoder = Budgeted::new(Decoder::default(), None);
    decoder.admit(b"n", true).unwrap();
    decoder.admit(b"r", true).unwrap();
    assert_eq!(decoder.usage(), (2, 1));
}
