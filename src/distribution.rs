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
}
