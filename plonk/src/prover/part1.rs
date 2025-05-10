pub fn run() -> () {
    println!("Executing part 1...");

    let number_gates = 3; // Circuit has 2 addition gates and 1 multiplication gate
    let number_inputs = 3; // Circuit has 2 public inputs (x1, x2) and 1 witness w
    let d = 3 * number_gates + number_inputs;
    assert_eq!(d, 12, "d must be equal to 12");
}
