import { useEffect, useState } from 'react';
import { AlertTriangle, Clock, X } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

/**
 * RateLimitToast - Toast notification for rate limit errors (429)
 *
 * Features:
 * - Auto-dismiss after countdown
 * - Retry countdown timer
 * - Manual dismiss
 * - Slide-in animation
 * - Multiple toasts support
 */
export default function RateLimitToast({ show, onClose, retryAfter = 60, message }) {
  const [countdown, setCountdown] = useState(retryAfter);

  useEffect(() => {
    if (!show) return;

    setCountdown(retryAfter);
    const interval = setInterval(() => {
      setCountdown((prev) => {
        if (prev <= 1) {
          clearInterval(interval);
          onClose?.();
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [show, retryAfter, onClose]);

  if (!show) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0, y: -50, scale: 0.9 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        exit={{ opacity: 0, y: -50, scale: 0.9 }}
        transition={{ duration: 0.3, type: 'spring' }}
        className="fixed top-4 right-4 z-50 max-w-md"
      >
        <div className="bg-gradient-to-r from-orange-900/90 to-red-900/90 backdrop-blur-xl border border-orange-500/50 rounded-xl shadow-2xl overflow-hidden">
          {/* Header with icon and close */}
          <div className="flex items-start gap-3 p-4">
            <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-orange-500/20 flex items-center justify-center">
              <AlertTriangle className="w-5 h-5 text-orange-400" />
            </div>

            <div className="flex-1 min-w-0">
              <h4 className="text-sm font-semibold text-white mb-1">
                Rate Limit Exceeded
              </h4>
              <p className="text-xs text-orange-200/80 leading-relaxed">
                {message || 'You have exceeded the rate limit for this operation. Please wait before trying again.'}
              </p>
            </div>

            <button
              onClick={onClose}
              className="flex-shrink-0 w-6 h-6 rounded-lg hover:bg-white/10 flex items-center justify-center transition-colors"
              aria-label="Close"
            >
              <X className="w-4 h-4 text-gray-400" />
            </button>
          </div>

          {/* Countdown timer */}
          <div className="px-4 pb-4">
            <div className="flex items-center justify-between gap-3 p-3 bg-black/30 rounded-lg">
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-cyan-400" />
                <span className="text-xs text-gray-300">Retry in</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-lg font-mono font-bold text-white">
                  {Math.floor(countdown / 60)}:{(countdown % 60).toString().padStart(2, '0')}
                </span>
                <span className="text-xs text-gray-400">min</span>
              </div>
            </div>
          </div>

          {/* Progress bar */}
          <div className="h-1 bg-black/30">
            <motion.div
              className="h-full bg-gradient-to-r from-orange-500 to-red-500"
              initial={{ width: '100%' }}
              animate={{ width: '0%' }}
              transition={{ duration: retryAfter, ease: 'linear' }}
            />
          </div>
        </div>
      </motion.div>
    </AnimatePresence>
  );
}

/**
 * useRateLimitToast - Hook for managing rate limit toasts
 *
 * Usage:
 * const { showToast, ToastComponent } = useRateLimitToast();
 *
 * // Show toast
 * showToast({ retryAfter: 60, message: 'Custom message' });
 *
 * // Render in component
 * return <>{ToastComponent}</>
 */
export function useRateLimitToast() {
  const [toasts, setToasts] = useState([]);

  const showToast = ({ retryAfter = 60, message } = {}) => {
    const id = Date.now();
    setToasts((prev) => [...prev, { id, retryAfter, message, show: true }]);
  };

  const hideToast = (id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  const ToastComponent = (
    <>
      {toasts.map((toast, index) => (
        <div key={toast.id} style={{ top: `${4 + index * 8}rem` }} className="fixed right-4 z-50">
          <RateLimitToast
            show={toast.show}
            retryAfter={toast.retryAfter}
            message={toast.message}
            onClose={() => hideToast(toast.id)}
          />
        </div>
      ))}
    </>
  );

  return { showToast, ToastComponent };
}
