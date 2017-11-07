#[macro_use]
extern crate holmes;
use holmes::simple::*;
extern crate tiamat;

#[test]
pub fn chop_2() {
    single(&|holmes, core| {
        tiamat::uaf(vec!["./samples/chops/2.so".to_string()], 20, false)(holmes, core)?;
        assert_eq!(query!(holmes, use_after_free_flow([_]))?.len(), 1);
        let res = query!(holmes, use_after_free {source = source, alias_set = alias_set})?;
        assert!(res.len() > 0);
        println!("chop 2: {} {}", res[0][0], res[0][1]);
        Ok(())
    })
}

#[test]
pub fn chop_14() {
    single(&|holmes, core| {
        tiamat::uaf(vec!["./samples/chops/14.so".to_string()], 30, true)(holmes, core)?;
        assert_eq!(query!(holmes, use_after_free_flow([_]))?.len(), 1);
        let res = query!(holmes, use_after_free {source = source, alias_set = alias_set})?;
        assert!(res.len() > 0);
        println!("chop 14: {} {}", res[0][0], res[0][1]);
        Ok(())
    })
}

#[test]
pub fn chop_4() {
    single(&|holmes, core| {
        tiamat::uaf(vec!["./samples/chops/4.so".to_string()], 48, false)(holmes, core)?;
        assert_eq!(query!(holmes, use_after_free_flow([_]))?.len(), 1);
        let res = query!(holmes, use_after_free {source = source, alias_set = alias_set})?;
        assert!(res.len() > 0);
        println!("chop 4: {} {}", res[0][0], res[0][1]);
        Ok(())
    })
}
