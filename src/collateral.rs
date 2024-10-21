use crate::distribution::ValueDistribution;

/// Collateral function f(n, D) from Theorem 21.
pub fn collateral_requirement<D: ValueDistribution>(n: usize, dist: &D, alpha: f64) -> f64 {
    assert!(n > 0, "number of buyers must be positive");
    assert!(alpha > 0.0, "alpha must be positive");
    let reserve = dist.reserve_price();
    if alpha >= 1.0 {
        return reserve;
    }
    let n_term = (n as f64 / alpha).powf((1.0 - alpha) / alpha);
    let hazard_term = (1.0 / (1.0 - alpha)).powf(1.0 / alpha);
    reserve * n_term * hazard_term
}
