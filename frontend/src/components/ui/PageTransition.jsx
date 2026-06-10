import React from 'react'
import { motion, useReducedMotion } from 'framer-motion'

/**
 * Optional page wrapper — subtle fade on mount. Wrap route outlets or page roots
 * when you want consistent enter transitions without animating every route by default.
 */
export default function PageTransition({ children, className = '' }) {
  const reduceMotion = useReducedMotion()

  if (reduceMotion) {
    return <div className={className}>{children}</div>
  }

  return (
    <motion.div
      className={className}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
    >
      {children}
    </motion.div>
  )
}
