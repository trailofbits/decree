use decree::decree::Decree;

// Decree::new tests
#[test]
fn test_invalid_labels()
{
    let invalid_labels: Vec<&'static str> = Vec::new();
    match Decree::new("test", invalid_labels, vec!["challenge1"]) {
        Ok(_) => { panic!("test_invalid_labels failure"); },
        Err(e) => { assert_eq!(e, "Must specify at least one input"); },
    }
}

#[test]
fn test_invalid_challenges()
{
    let invalid_challenges: Vec<&'static str> = Vec::new();
    match Decree::new("test", vec!["input1"], invalid_challenges) {
        Ok(_) => { panic!("test_invalid_challenges failure"); },
        Err(e) => { assert_eq!(e, "Must specify at least one challenge"); },
    }
}


// Decree::add_input tests
#[test]
fn test_add_invalid_label()
{
    let buf: [u8; 32] = [0xffu8; 32];
    let mut my_decree = match Decree::new("test", vec!["input1"], vec!["challenge1"]) {
        Ok(dec) => dec,
        Err(_) => { panic!("test_add_invalid_label failed to create Decree"); }
    };

    match my_decree.add_bytes("invalid_label", &buf.to_vec()) {
        Ok(_) => { panic!("test_add_invalid_label failure"); },
        Err(e) => { assert_eq!(e, "Invalid label"); },
    }
}

#[test]
fn test_add_label_twice()
{
    let buf: [u8; 32] = [0xffu8; 32];
    let mut my_decree = match Decree::new("test", vec!["input1", "input2"], vec!["challenge1"]) {
        Ok(dec) => dec,
        Err(_) => { panic!("test_add_invalid_label failed to create Decree"); }
    };

    match my_decree.add_bytes("input1", &buf.to_vec()) {
        Err(_) => { panic!("test_add_label_twice failure"); },
        Ok(_) => { },
    }

    match my_decree.add_bytes("input1", &buf.to_vec()) {
        Ok(_) => { panic!("test_add_label_twice failure"); },
        Err(e) => { assert_eq!(e, "Label already used"); },
    }
}

#[test]
fn test_add_post_commit()
{
    let buf: [u8; 32] = [0xffu8; 32];
    let mut my_decree = match Decree::new("test", vec!["input1", "input2"], vec!["challenge1"]) {
        Ok(dec) => dec,
        Err(_) => { panic!("test_add_post_commit failed to create Decree"); }
    };

    match my_decree.add_bytes("input1", &buf.to_vec()) {
        Err(_) => { panic!("test_add_post_commit failure"); },
        Ok(_) => { },
    }

    match my_decree.add_bytes("input2", &buf.to_vec()) {
        Err(_) => { panic!("test_add_post_commit failure"); },
        Ok(_) => { },
    }

    match my_decree.add_bytes("input2", &buf.to_vec()) {
        Ok(_) => { panic!("test_add_post_commit failure"); },
        Err(e) => { assert_eq!(e, "Cannot add values after commitment"); }
    }
}

// Decree::get_challenge tests
#[test]
fn test_challenge_unspec()
{
    let buf: [u8; 32] = [0xffu8; 32];
    let mut my_decree = match Decree::new("test", vec!["input1"], vec!["challenge1"]) {
        Ok(dec) => dec,
        Err(_) => { panic!("test_challenge_unspec failed to create Decree"); }
    };

    match my_decree.add_bytes("input1", &buf.to_vec()) {
        Ok(_) => { },
        Err(_) => { panic!("test_challenge_unspec failure"); },
    }

    let mut out_buffer: [u8; 64] = [0u8; 64];
    match my_decree.get_challenge("invalid_challenge", &mut out_buffer) {
        Ok(_) => { panic!("test_challenge_unspec failure"); }
        Err(e) => { assert_eq!(e, "Requested challenge not in spec"); }
    }
}

#[test]
fn test_challenge_order()
{
    let buf: [u8; 32] = [0xffu8; 32];
    let mut my_decree = match Decree::new("test", vec!["input1"], vec!["challenge1", "challenge2"]) {
        Ok(dec) => dec,
        Err(_) => { panic!("test_challenge_order failed to create Decree"); }
    };

    match my_decree.add_bytes("input1", &buf.to_vec()) {
        Ok(_) => { },
        Err(_) => { panic!("test_challenge_order failure"); },
    }

    let mut out_buffer: [u8; 64] = [0u8; 64];
    match my_decree.get_challenge("challenge2", &mut out_buffer) {
        Ok(_) => { panic!("test_challenge_order failure"); }
        Err(e) => { assert_eq!(e, "Challenge order incorrect"); }
    }
}

#[test]
fn test_challenges_empty()
{
    let mut my_decree = match Decree::new("test", vec!["input1"], vec!["challenge1"]) {
        Ok(dec) => dec,
        Err(_) => { panic!("test_challenges_empty failed to create Decree"); },
    };

    let buf: [u8; 32] = [0xffu8; 32];
    match my_decree.add_bytes("input1", &buf.to_vec()) {
        Ok(_) => { },
        Err(_) => { panic!("test_challenges_empty failure"); },
    }

    let mut out_buffer: [u8; 64] = [0u8; 64];

    match my_decree.get_challenge("challenge1", &mut out_buffer) {
        Err(_) => { panic!("test_challenges_empty failure"); }
        Ok(_) => { },
    }

    match my_decree.get_challenge("challenge2", &mut out_buffer) {
        Ok(_) => { panic!("test_challenges_empty failure"); }
        Err(e) => { assert_eq!(e, "No remaining challenges"); },
    }
}

#[test]
fn test_challenge_not_ready()
{
    let mut my_decree = match Decree::new("test", vec!["input1", "input2"], vec!["challenge1"]) {
        Ok(dec) => dec,
        Err(_) => { panic!("test_challenge_not_ready failed to create Decree"); },
    };

    let buf: [u8; 32] = [0xffu8; 32];
    match my_decree.add_bytes("input1", &buf.to_vec()) {
        Ok(_) => { },
        Err(_) => { panic!("test_challenges_empty failure"); },
    }

    let mut out_buffer: [u8; 64] = [0u8; 64];

    match my_decree.get_challenge("challenge1", &mut out_buffer) {
        Ok(_) => { panic!("test_challenge_not_ready failure"); },
        Err(e) => { assert_eq!(e, "Missing transcript parameters"); }
    }
}
