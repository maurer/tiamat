#[macro_use]
extern crate holmes;
use holmes::simple::*;
extern crate tiamat;

#[test]
pub fn chop_2() {
    single(&|holmes, core| {
        tiamat::uaf(vec!["./samples/chops/2.so".to_string()], 20)(holmes, core)?;
        assert_eq!(query!(holmes, use_after_free_flow([_]))?.len(), 1);
        assert!(query!(holmes, use_after_free([_]))?.len() >  0);
        Ok(())
    })
}

#[test]
pub fn chop_14() {
    single(&|holmes, core| {
        tiamat::uaf(vec!["./samples/chops/14.so".to_string()], 30)(holmes, core)?;
        assert_eq!(query!(holmes, use_after_free_flow([_]))?.len(), 1);
        assert!(query!(holmes, use_after_free([_]))?.len() > 0);
        Ok(())
    })
}

#[test]
pub fn chop_4() {
    single(&|holmes, core| {
        tiamat::uaf(vec!["./samples/chops/4.so".to_string()], 48)(holmes, core)?;
        assert_eq!(query!(holmes, use_after_free_flow([_]))?.len(), 1);
        assert!(query!(holmes, use_after_free([_]))?.len() > 0);
        Ok(())
    })
}
