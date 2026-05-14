use proptest::prelude::*;

proptest! {
    #[test]
    fn dummy_proptest(x in 0..100i32) {
        assert!(x >= 0);
    }
}
