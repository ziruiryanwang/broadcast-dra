use crate::distribution::ValueDistribution;

/// Collateral threshold \(f(n,D)\) from Theorem 21 that deters shill withholding for
/// \(\alpha\)-strongly regular distributions.
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

/// Numerically approach the same collateral threshold using binary search.
/// Useful when plugging in custom reserve-price or hazard computations.
pub fn numeric_collateral_search<D: ValueDistribution>(
    n: usize,
    dist: &D,
    alpha: f64,
    tol: f64,
) -> f64 {
    let target = collateral_requirement(n, dist, alpha);
    let reserve = dist.reserve_price();
    let mut lo = reserve;
    let mut hi = target.max(reserve);
    for _ in 0..64 {
        let mid = 0.5 * (lo + hi);
        if (mid - target).abs() <= tol {
            return mid;
        }
        if mid < target {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    hi
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distribution::Exponential;

    #[test]
    fn numeric_search_matches_closed_form() {
        let dist = Exponential::new(1.0);
        let closed = collateral_requirement(3, &dist, 0.75);
        let numeric = numeric_collateral_search(3, &dist, 0.75, 1e-9);
        assert!((closed - numeric).abs() < 1e-6);
    }
}
