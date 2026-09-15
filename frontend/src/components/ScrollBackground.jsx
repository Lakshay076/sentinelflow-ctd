import React, { useState, useEffect } from "react";
import { motion, useScroll, useTransform } from "framer-motion";

export function ScrollBackground() {
  const [shouldAnimate, setShouldAnimate] = useState(true);
  
  useEffect(() => {
    // Check prefers-reduced-motion
    const mediaQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
    if (mediaQuery.matches) {
      setShouldAnimate(false);
    }
  }, []);

  const { scrollYProgress } = useScroll();

  // Opacity peaks in the middle of the page scroll
  const opacity = useTransform(
    scrollYProgress,
    [0, 0.4, 0.6, 1],
    [0, 0.8, 0.8, 0]
  );

  if (!shouldAnimate) return null;

  return (
    <div
      style={{
        position: "fixed",
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        pointerEvents: "none",
        zIndex: -1,
      }}
    >
      <motion.div
        style={{
          position: "absolute",
          inset: 0,
          background: "var(--accent-tint)",
          opacity,
        }}
      />
    </div>
  );
}
