#[macro_use]
extern crate holmes;
use holmes::simple::*;
extern crate tiamat;

#[test]
pub fn simple() {
    single(&|holmes, core| {
        tiamat::uaf(vec!["./samples/use_after_free/simple".to_string()])(holmes, core)?;
        assert_eq!(query!(holmes, use_after_free([_], [_], [_], [_], [_], [_], [_]))?.len(), 2);
        Ok(())
    })
}

#[test]
pub fn safe() {
    single(&|holmes, core| {
        tiamat::uaf(vec!["./samples/use_after_free/safe".to_string()])(holmes, core)?;
        assert_eq!(query!(holmes, use_after_free([_], [_], [_], [_], [_], [_], [_]))?.len(), 0);
        Ok(())
    })
}

#[test]
pub fn func() {
    single(&|holmes, core| {
        tiamat::uaf(vec!["./samples/use_after_free/func".to_string()])(holmes, core)?;
        assert_eq!(query!(holmes, use_after_free([_], [_], [_], [_], [_], [_], [_]))?.len(), 1);
        Ok(())
    })
}

#[test]
pub fn link() {
    single(&|holmes, core| {
        tiamat::uaf(vec!["./samples/use_after_free/func".to_string(),
                         "./samples/use_after_free/external.so".to_string()])(holmes, core)?;
        assert_eq!(query!(holmes, use_after_free_flow([_]))?.len(), 1);
        assert!(query!(holmes, use_after_free([_]))?.len() > 0);
        Ok(())
    })
}

#[test]
pub fn path_sensitive() {
    single(&|holmes, core| {
        tiamat::uaf(vec!["./samples/use_after_free/path_sensitive".to_string()])(holmes, core)?;
        assert_eq!(query!(holmes, use_after_free([_], [_], [_], [_], [_], [_], [_]))?.len(), 0);
        Ok(())
    })
}

#[test]
pub fn remalloc() {
    single(&|holmes, core| {
        tiamat::uaf(vec!["./samples/use_after_free/remalloc".to_string()])(holmes, core)?;
        assert_eq!(query!(holmes, use_after_free([_], [_], [_], [_], [_], [_], [_]))?.len(), 0);
        Ok(())
    })
}

#[test]
pub fn inf_trace() {
    single(&|holmes, core| {
        tiamat::uaf(vec!["./samples/use_after_free/loop".to_string()])(holmes, core)?;
        let mut out = query!(holmes, true_positive([_], [_], name))?;
        out.sort();
        out.dedup();
        assert_eq!(out.len(), 2);
        Ok(())
    })
}
