pub fn xor_array<A, B>(mut a: A, b: B) -> A
where
    A: AsMut<[u8]>,
    B: AsRef<[u8]>,
{
    a.as_mut()
        .iter_mut()
        .zip(b.as_ref())
        .for_each(|(a_i, b_i)| *a_i ^= *b_i);
    a
}
