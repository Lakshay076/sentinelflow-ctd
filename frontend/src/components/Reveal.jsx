import { motion, useReducedMotion } from "framer-motion";

export function Reveal({ children, delay = 0, yOffset = 16, duration = 0.4, className = "" }) {
  const shouldReduceMotion = useReducedMotion();

  if (shouldReduceMotion) {
    return <div className={className}>{children}</div>;
  }

  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y: yOffset }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-50px" }}
      transition={{ 
        duration: duration, 
        delay: delay, 
        ease: [0.25, 0.1, 0.25, 1] // Custom ease-out curve for premium feel
      }}
    >
      {children}
    </motion.div>
  );
}
