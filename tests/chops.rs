#[macro_use]
extern crate holmes;
use holmes::simple::*;
extern crate tiamat;
extern crate bap;
use bap::high::bitvector::BitVector;

#[test]
pub fn chop_2() {
    single(&|holmes, core| {
        tiamat::uaf(vec!["./samples/chops/2.so".to_string()], 20, false)(holmes, core)?;
        assert_eq!(query!(holmes, use_after_free_flow([_]))?.len(), 1);
        let res = query!(holmes, use_after_free {source = source, alias_set = alias_set})?;
        assert!(res.len() > 0);
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
        Ok(())
    })
}

#[test]
pub fn chop_7() {
    single(&|holmes, core| {
        tiamat::uaf(vec!["./samples/chops/7.so".to_string()], 31, false)(holmes, core)?;
        assert!(query!(holmes, use_after_free_flow([_]))?.len() > 1);
        let res = query!(holmes, use_after_free {source = source, alias_set = alias_set})?;
        assert!(res.len() > 0);
        for row in res {
            assert!((&row[0] == &BitVector::from_u64(0x578b, 64).to_value())
                    || (&row[0] == &BitVector::from_u64(0x84f3, 64).to_value())
                    || (&row[0] == &BitVector::from_u64(0x8545, 64).to_value()));
        }
        Ok(())
    })
}
