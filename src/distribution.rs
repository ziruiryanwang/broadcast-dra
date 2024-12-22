use rand::Rng;
use rand_distr::{Distribution as RandDistribution, Exp, LogNormal as RandLogNormal};
use statrs::distribution::{ContinuousCDF, Normal};

/// A value distribution supporting the quantities used in the paper.
pub trait ValueDistribution: Clone {
    /// Cumulative density function.
    fn cdf(&self, x: f64) -> f64;
    /// Probability density function.
    fn pdf(&self, x: f64) -> f64;

    /// Virtual value function: φ(x) = x - (1-F(x))/f(x).
    fn virtual_value(&self, x: f64) -> f64 {
        let f = self.pdf(x);
        if f <= f64::EPSILON {
            return f64::NEG_INFINITY;
        }
        let one_minus_f = 1.0 - self.cdf(x);
        x - (one_minus_f / f)
    }

    /// Myerson reserve price r(D) defined by φ(r)=0.
    fn reserve_price(&self) -> f64 {
        let mut lo = 0.0_f64;
        let mut hi = 1.0_f64;
        // Expand until we bracket a non-negative virtual value.
        for _ in 0..64 {
            if self.virtual_value(hi) >= 0.0 {
                break;
            }
            hi *= 2.0;
        }
        // If still negative, fall back to hi as best-effort.
        if self.virtual_value(hi) < 0.0 {
            return hi;
        }
        for _ in 0..96 {
            let mid = 0.5 * (lo + hi);
            if self.virtual_value(mid) >= 0.0 {
                hi = mid;
            } else {
                lo = mid;
            }
        }
        hi
    }

    /// α such that the distribution is α-strongly regular, if known.
    fn strong_regular_alpha(&self) -> Option<f64> {
        None
    }

    /// Sample a value from the distribution.
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> f64;
}

#[derive(Clone, Debug)]
pub struct Exponential {
    pub lambda: f64,
}

impl Exponential {
    pub fn new(lambda: f64) -> Self {
        assert!(lambda > 0.0, "lambda must be positive");
        Self { lambda }
    }
}

impl ValueDistribution for Exponential {
    fn cdf(&self, x: f64) -> f64 {
        if x <= 0.0 {
            0.0
        } else {
            1.0 - (-self.lambda * x).exp()
        }
    }

    fn pdf(&self, x: f64) -> f64 {
        if x <= 0.0 {
            0.0
        } else {
            self.lambda * (-self.lambda * x).exp()
        }
    }

    fn virtual_value(&self, x: f64) -> f64 {
        x - 1.0 / self.lambda
    }

    fn reserve_price(&self) -> f64 {
        1.0 / self.lambda
    }

    fn strong_regular_alpha(&self) -> Option<f64> {
        Some(1.0)
    }

    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> f64 {
        let exp = Exp::new(self.lambda).expect("lambda > 0");
        exp.sample(rng)
    }
}

#[derive(Clone, Debug)]
pub struct Uniform {
    pub low: f64,
    pub high: f64,
}

impl Uniform {
    pub fn new(low: f64, high: f64) -> Self {
        assert!(low < high, "uniform requires low < high");
        Self { low, high }
    }
}

impl ValueDistribution for Uniform {
    fn cdf(&self, x: f64) -> f64 {
        if x <= self.low {
            0.0
        } else if x >= self.high {
            1.0
        } else {
            (x - self.low) / (self.high - self.low)
        }
    }

    fn pdf(&self, x: f64) -> f64 {
        if x < self.low || x > self.high {
            0.0
        } else {
            1.0 / (self.high - self.low)
        }
    }

    fn virtual_value(&self, x: f64) -> f64 {
        x - (1.0 - self.cdf(x)) / self.pdf(x)
    }

    fn reserve_price(&self) -> f64 {
        // φ(x) = 2x - high => root at high/2
        0.5 * self.high
    }

    fn strong_regular_alpha(&self) -> Option<f64> {
        // φ'(x) = 2, so any α <= 2 is valid. Report the tight value.
        Some(2.0)
    }

    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> f64 {
        rng.gen_range(self.low..self.high)
    }
}

#[derive(Clone, Debug)]
pub struct Pareto {
    pub scale: f64,
    pub shape: f64,
}

impl Pareto {
    pub fn new(scale: f64, shape: f64) -> Self {
        assert!(scale > 0.0, "scale must be positive");
        assert!(shape > 0.0, "shape must be positive");
        Self { scale, shape }
    }
}

impl ValueDistribution for Pareto {
    fn cdf(&self, x: f64) -> f64 {
        if x < self.scale {
            0.0
        } else {
            1.0 - (self.scale / x).powf(self.shape)
        }
    }

    fn pdf(&self, x: f64) -> f64 {
        if x < self.scale {
            0.0
        } else {
            self.shape * self.scale.powf(self.shape) / x.powf(self.shape + 1.0)
        }
    }

    fn virtual_value(&self, x: f64) -> f64 {
        // φ(x) = x - (1-F)/f = x - x/shape
        x * (1.0 - 1.0 / self.shape)
    }

    fn reserve_price(&self) -> f64 {
        // φ is positive for x >= scale if shape>1; use scale as reserve.
        self.scale
    }

    fn strong_regular_alpha(&self) -> Option<f64> {
        if self.shape > 1.0 {
            Some(1.0 - 1.0 / self.shape)
        } else {
            None
        }
    }

    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> f64 {
        let u: f64 = rng.gen_range(0.0..1.0);
        self.scale / u.powf(1.0 / self.shape)
    }
}

#[derive(Clone, Debug)]
pub struct LogNormal {
    pub mu: f64,
    pub sigma: f64,
}

impl LogNormal {
    pub fn new(mu: f64, sigma: f64) -> Self {
        assert!(sigma > 0.0, "sigma must be positive");
        Self { mu, sigma }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pareto_virtual_value_matches_formula() {
        let p = Pareto::new(2.0, 3.0);
        let x = 5.0;
        let direct = p.virtual_value(x);
        let expected = x * (1.0 - 1.0 / 3.0);
        assert!((direct - expected).abs() < 1e-9);
    }

    #[test]
    fn sampling_produces_support_values() {
        let mut rng = rand::thread_rng();
        let u = Uniform::new(1.0, 2.0);
        let x = u.sample(&mut rng);
        assert!(x >= 1.0 && x <= 2.0);

        let e = Exponential::new(1.0);
        assert!(e.sample(&mut rng) >= 0.0);

        let p = Pareto::new(1.0, 2.0);
        assert!(p.sample(&mut rng) >= 1.0);

        let ln = LogNormal::new(0.0, 1.0);
        assert!(ln.sample(&mut rng) > 0.0);
    }
}

impl ValueDistribution for LogNormal {
    fn cdf(&self, x: f64) -> f64 {
        if x <= 0.0 {
            return 0.0;
        }
        let normal = Normal::new(self.mu, self.sigma).expect("valid normal");
        normal.cdf(x.ln())
    }

    fn pdf(&self, x: f64) -> f64 {
        if x <= 0.0 {
            return 0.0;
        }
        let coeff = 1.0 / (x * self.sigma * (2.0 * std::f64::consts::PI).sqrt());
        let z = (x.ln() - self.mu) / self.sigma;
        coeff * (-0.5 * z * z).exp()
    }

    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> f64 {
        let dist = RandLogNormal::new(self.mu, self.sigma).expect("valid lognormal");
        dist.sample(rng)
    }
}

/// Equal-revenue distribution used in the Theorem 25 counterexample: F(x)=1-scale/x for x>=scale.
#[derive(Clone, Debug)]
pub struct EqualRevenue {
    pub scale: f64,
}

impl EqualRevenue {
    pub fn new(scale: f64) -> Self {
        assert!(scale > 0.0, "scale must be positive");
        Self { scale }
    }
}

impl ValueDistribution for EqualRevenue {
    fn cdf(&self, x: f64) -> f64 {
        if x < self.scale {
            0.0
        } else {
            1.0 - self.scale / x
        }
    }

    fn pdf(&self, x: f64) -> f64 {
        if x < self.scale {
            0.0
        } else {
            self.scale / (x * x)
        }
    }

    fn virtual_value(&self, x: f64) -> f64 {
        if x < self.scale {
            f64::NEG_INFINITY
        } else {
            0.0
        }
    }

    fn reserve_price(&self) -> f64 {
        self.scale
    }

    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> f64 {
        let u: f64 = rng.gen_range(0.0..1.0);
        self.scale / (1.0 - u)
    }
}
