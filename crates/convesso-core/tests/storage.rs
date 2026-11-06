//! The storage scenarios: memory for the core's tables is supplied by the
//! integrator (`DESIGN.md §2`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use convesso_core::storage::{CapacityExhausted, Config, Empty, FixedTable, Mcu, Table, TableFull};
use proptest::prelude::*;

/// Scenario: insertion within capacity succeeds.
#[test]
fn insertion_within_capacity_succeeds() {
    let mut table: FixedTable<u8, &str, 2> = FixedTable::new();

    assert_eq!(table.insert(1, "one"), Ok(None));
    assert_eq!(table.insert(2, "two"), Ok(None));

    assert_eq!(table.get(&1), Some(&"one"));
    assert_eq!(table.get(&2), Some(&"two"));
    assert_eq!(table.len(), 2);
}

/// Scenario: insertion into a full table is refused, with the entry handed back
/// and every entry previously held unchanged.
#[test]
fn insertion_into_a_full_table_is_refused() {
    let mut table: FixedTable<u8, &str, 2> = FixedTable::new();
    table.insert(1, "one").unwrap();
    table.insert(2, "two").unwrap();

    let refused = table.insert(3, "three");

    assert_eq!(
        refused,
        Err(CapacityExhausted {
            key: 3,
            value: "three",
            capacity: 2
        })
    );
    assert_eq!(table.get(&1), Some(&"one"));
    assert_eq!(table.get(&2), Some(&"two"));
    assert_eq!(table.get(&3), None);
    assert_eq!(table.len(), 2);
}

/// The refusal names its condition, so a caller can report it.
#[test]
fn the_refusal_names_the_condition() {
    let mut table: FixedTable<u8, (), 1> = FixedTable::new();
    table.insert(1, ()).unwrap();

    let error = table.insert(2, ()).unwrap_err();

    assert_eq!(
        error.to_string(),
        "table capacity exhausted: all 1 entries are in use"
    );
}

/// Replacing the value of a key already held needs no room, even when full.
#[test]
fn replacing_a_held_key_succeeds_when_full() {
    let mut table: FixedTable<u8, &str, 1> = FixedTable::new();
    table.insert(1, "old").unwrap();

    assert_eq!(table.insert(1, "new"), Ok(Some("old")));
    assert_eq!(table.get(&1), Some(&"new"));
}

/// A slot freed by a removal is used again.
#[test]
fn a_removed_entry_frees_its_slot() {
    let mut table: FixedTable<u8, (), 1> = FixedTable::new();
    table.insert(1, ()).unwrap();
    assert_eq!(table.remove(&1), Some(()));

    assert_eq!(table.insert(2, ()), Ok(None));
    assert_eq!(table.remove(&1), None);
}

/// The microcontroller configuration has the stated, fixed capacities.
#[test]
fn the_microcontroller_configuration_is_fixed() {
    let sessions: <Mcu as Config>::Sessions<u8, ()> = Default::default();
    let peers: <Mcu as Config>::Peers<u8, ()> = Default::default();

    assert_eq!(sessions.capacity(), Some(4));
    assert_eq!(peers.capacity(), Some(16));
}

convesso_core::profile! {
    /// A device with two contexts and eight sessions.
    Device: Mcu { contexts: 2, sessions: 8 }
}

/// Scenario: a profile derived from the reference changes only what it names.
/// (That a name which is not a size fails to build is `profile!`'s
/// `compile_fail` example.)
#[test]
fn a_derived_profile_changes_only_what_it_names() {
    use convesso_core::storage::Sizes;

    assert_eq!(
        Device::SIZES,
        Sizes {
            contexts: 2,
            sessions: 8,
            ..Mcu::SIZES
        }
    );

    let contexts: <Device as Config>::Contexts<u8, ()> = Default::default();
    let sessions: <Device as Config>::Sessions<u8, ()> = Default::default();
    let peers: <Device as Config>::Peers<u8, ()> = Default::default();
    let pending: <Device as Config>::Pending<u8, ()> = Default::default();
    assert_eq!(contexts.capacity(), Some(2));
    assert_eq!(sessions.capacity(), Some(8));
    assert_eq!(peers.capacity(), Some(16));
    assert_eq!(pending.capacity(), Some(4));
    assert_eq!(<Device as Config>::LOAD_RATE_PER_SECOND, 5);
}

/// Scenario: growable storage accepts beyond any fixed capacity, under the same
/// trait the protocol logic is written against.
#[cfg(feature = "alloc")]
#[test]
fn growable_storage_accepts_beyond_any_fixed_capacity() {
    use convesso_core::storage::Server;

    fn fill<T: Table<u32, u32>>(table: &mut T, count: u32) {
        for key in 0..count {
            assert_eq!(table.insert(key, key), Ok(None));
        }
    }

    let mut table: <Server as Config>::Sessions<u32, u32> = Default::default();
    fill(&mut table, 10_000);

    assert_eq!(table.len(), 10_000);
    assert_eq!(table.capacity(), None);
    assert_eq!(table.get(&9_999), Some(&9_999));
}

#[derive(Debug, Clone)]
enum Op {
    Insert(u8, u32),
    Remove(u8),
    InsertEmpty(u8, u32),
    Discard(u8),
}

fn op() -> impl Strategy<Value = Op> {
    // Keys from a small range, so that inserts collide, replace and fill up.
    prop_oneof![
        (0u8..8, any::<u32>()).prop_map(|(k, v)| Op::Insert(k, v)),
        (0u8..8).prop_map(Op::Remove),
        (0u8..8, any::<u32>()).prop_map(|(k, v)| Op::InsertEmpty(k, v)),
        (0u8..8).prop_map(Op::Discard),
    ]
}

/// A table's value with an empty state: what `insert_empty` makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Value(u32);

impl Empty for Value {
    const EMPTY: Self = Self(0);
}

/// Applies `ops` to `table` and to a model holding at most `capacity`
/// entries, and checks that they agree after each: what each operation
/// returns, what the table holds, and that `insert_empty` makes an empty
/// entry only for a new key that fits, which the caller then fills.
fn agrees_with_its_model(
    table: &mut impl Table<u8, Value>,
    capacity: usize,
    ops: Vec<Op>,
) -> Result<(), TestCaseError> {
    let mut model = std::collections::BTreeMap::new();
    for op in ops {
        match op {
            Op::Insert(k, v) => {
                let v = Value(v);
                let result = table.insert(k, v);
                if model.contains_key(&k) || model.len() < capacity {
                    prop_assert_eq!(result, Ok(model.insert(k, v)));
                } else {
                    prop_assert_eq!(
                        result,
                        Err(CapacityExhausted {
                            key: k,
                            value: v,
                            capacity
                        })
                    );
                }
            }
            Op::Remove(k) => prop_assert_eq!(table.remove(&k), model.remove(&k)),
            Op::InsertEmpty(k, v) => {
                let held = model.get(&k).copied();
                let room = model.len() < capacity;
                match table.insert_empty(k) {
                    Ok(entry) => {
                        prop_assert!(held.is_some() || room);
                        // A held entry comes back as it is; a new one empty,
                        // and the caller fills it.
                        prop_assert_eq!(*entry, held.unwrap_or(Value::EMPTY));
                        if held.is_none() {
                            *entry = Value(v);
                            model.insert(k, Value(v));
                        }
                    }
                    Err(full) => {
                        prop_assert!(held.is_none() && !room);
                        prop_assert_eq!(full, TableFull { capacity });
                    }
                }
            }
            Op::Discard(k) => prop_assert_eq!(table.discard(&k), model.remove(&k).is_some()),
        }
        prop_assert_eq!(table.len(), model.len());
        prop_assert_eq!(table.first(), model.first_key_value());
        for k in 0u8..8 {
            prop_assert_eq!(table.get(&k), model.get(&k));
        }
    }
    Ok(())
}

proptest! {
    /// Any sequence of inserts and removes, made or dropped in place or not,
    /// leaves a fixed table agreeing with a model that holds at most its
    /// capacity, and never panics.
    #[test]
    fn a_fixed_table_agrees_with_its_model(ops in proptest::collection::vec(op(), 0..200)) {
        agrees_with_its_model(&mut FixedTable::<u8, Value, 4>::new(), 4, ops)?;
    }

    /// The same for a growable table with a limit.
    #[cfg(feature = "alloc")]
    #[test]
    fn a_growable_table_agrees_with_its_model(ops in proptest::collection::vec(op(), 0..200)) {
        let mut table = convesso_core::storage::GrowableTable::<u8, Value, 4>::new();
        agrees_with_its_model(&mut table, 4, ops)?;
    }
}

/// `retain` keeps exactly what it is told to, and `for_each` sees every entry.
#[test]
fn retain_and_for_each_see_every_entry() {
    let mut table: FixedTable<u8, u32, 4> = FixedTable::new();
    for k in 0..4 {
        table.insert(k, u32::from(k) * 10).unwrap();
    }
    table.retain(|k, _| k % 2 == 0);
    assert_eq!(table.len(), 2);
    let mut seen = Vec::new();
    table.for_each(|k, v| seen.push((*k, *v)));
    seen.sort_unstable();
    assert_eq!(seen, vec![(0, 0), (2, 20)]);
    // The freed slots are usable again.
    assert_eq!(table.insert(9, 90), Ok(None));
}

/// A growable table with a limit refuses a new key at the limit, like a fixed one.
#[cfg(feature = "alloc")]
#[test]
fn a_growable_table_with_a_limit_refuses_at_the_limit() {
    use convesso_core::storage::GrowableTable;

    let mut table: GrowableTable<u8, (), 2> = GrowableTable::new();
    table.insert(1, ()).unwrap();
    table.insert(2, ()).unwrap();
    assert_eq!(table.capacity(), Some(2));
    assert_eq!(
        table.insert(3, ()),
        Err(CapacityExhausted {
            key: 3,
            value: (),
            capacity: 2
        })
    );
    assert_eq!(table.insert(2, ()), Ok(Some(())));
    let pending: <convesso_core::storage::Server as Config>::Pending<u8, ()> = Default::default();
    assert_eq!(pending.capacity(), Some(4096));
}

/// The smallest key whatever the order of insertion, and the next one once it
/// is removed: what an index ordered by time holds next.
fn first_follows_the_keys(table: &mut impl Table<u32, char>) {
    assert_eq!(table.first(), None);
    for (key, value) in [(30, 'c'), (10, 'a'), (20, 'b')] {
        table.insert(key, value).unwrap();
    }
    assert_eq!(table.first(), Some((&10, &'a')));
    table.remove(&10);
    assert_eq!(table.first(), Some((&20, &'b')));
    table.insert(5, 'z').unwrap();
    assert_eq!(table.first(), Some((&5, &'z')));
    table.retain(|_, _| false);
    assert_eq!(table.first(), None);
}

#[test]
fn a_fixed_table_gives_its_smallest_key() {
    first_follows_the_keys(&mut FixedTable::<u32, char, 4>::new());
}

#[cfg(feature = "alloc")]
#[test]
fn a_growable_table_gives_its_smallest_key() {
    first_follows_the_keys(&mut convesso_core::storage::GrowableTable::<u32, char>::new());
}

/// A table built at compile time, in a `static`: what an integrator places
/// its state in.
static EMPTY_TABLE: FixedTable<u32, Value, 4> = FixedTable::EMPTY;

#[test]
fn a_table_is_built_empty_at_compile_time() {
    assert!(EMPTY_TABLE.is_empty());
    assert_eq!(EMPTY_TABLE.capacity(), Some(4));
    let mut table = <FixedTable<u32, Value, 4> as Table<_, _>>::EMPTY;
    let entry = table.insert_empty(1).unwrap();
    assert_eq!(*entry, Value::EMPTY);
    *entry = Value(7);
    assert_eq!(table.get(&1), Some(&Value(7)));
    assert!(table.discard(&1));
    assert!(!table.discard(&1));
    assert!(table.is_empty());
}

/// A full table refuses a new key without making its entry, and every entry
/// it held is unchanged.
#[test]
fn a_full_table_refuses_without_making_the_entry() {
    let mut table: FixedTable<u8, Value, 2> = FixedTable::new();
    *table.insert_empty(1).unwrap() = Value(10);
    *table.insert_empty(2).unwrap() = Value(20);
    let refused = table.insert_empty(3);
    assert_eq!(refused, Err(TableFull { capacity: 2 }));
    assert_eq!(
        refused.unwrap_err().to_string(),
        "table capacity exhausted: all 2 entries are in use"
    );
    assert_eq!(
        (table.get(&1), table.get(&2), table.get(&3)),
        (Some(&Value(10)), Some(&Value(20)), None)
    );
}

/// A key already held gives its entry back, as it is, without emptying it.
#[test]
fn a_held_key_gives_its_entry_as_it_is() {
    let mut table: FixedTable<u8, Value, 2> = FixedTable::new();
    *table.insert_empty(1).unwrap() = Value(10);
    table.insert_empty(1).unwrap().0 += 1;
    assert_eq!(table.get(&1), Some(&Value(11)));
    assert_eq!(table.len(), 1);
}
