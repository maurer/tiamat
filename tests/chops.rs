#[macro_use]
extern crate holmes;
use holmes::simple::*;
extern crate tiamat;

#[test]
pub fn chop_2() {
    single(&|holmes, core| {
        tiamat::uaf(vec!["./samples/chops/2.so".to_string()])(holmes, core)?;
        assert_eq!(query!(holmes, use_after_free_flow([_]))?.len(), 1);
        assert!(query!(holmes, use_after_free([_]))?.len() >  0);
        Ok(())
    })
}
