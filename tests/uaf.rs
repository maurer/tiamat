#[macro_use]
extern crate holmes;
use holmes::simple::*;
extern crate tiamat;

#[test]
pub fn simple() {
    single(&|holmes, core| {
        tiamat::uaf(vec!["./samples/use_after_free/simple".to_string()])(holmes, core)?;
        assert_eq!(query!(holmes, use_after_free([_], [_], [_], [_], [_], [_]))?.len(), 2);
        Ok(())
    })
}

#[test]
pub fn safe() {
    single(&|holmes, core| {
        tiamat::uaf(vec!["./samples/use_after_free/safe".to_string()])(holmes, core)?;
        assert_eq!(query!(holmes, use_after_free([_], [_], [_], [_], [_], [_]))?.len(), 0);
        Ok(())
    })
}
