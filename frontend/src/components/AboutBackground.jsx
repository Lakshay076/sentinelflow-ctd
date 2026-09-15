import React, { useEffect, useRef } from "react";
import { useMotionValue, useSpring } from "framer-motion";

export function AboutBackground() {
  const canvasRef = useRef(null);

  // Smooth mouse tracking
  const mouseX = useMotionValue(typeof window !== "undefined" ? window.innerWidth / 2 : 0);
  const mouseY = useMotionValue(typeof window !== "undefined" ? window.innerHeight / 2 : 0);
  const springConfig = { damping: 40, stiffness: 100, mass: 1 };
  const smoothX = useSpring(mouseX, springConfig);
  const smoothY = useSpring(mouseY, springConfig);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationFrameId;
    let particles = [];
    let width = window.innerWidth;
    let height = window.innerHeight;

    // Check motion preference
    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const isTouch = window.matchMedia("(pointer: coarse)").matches;

    // Node count responsive to screen size
    const getParticleCount = () => {
      if (width < 768) return 30;
      if (width < 1200) return 50;
      return 80;
    };

    // Colors that adapt to theme
    const getColors = () => {
      // Determine if we are in dark mode by checking the computed background color
      const bgPrimary = getComputedStyle(document.documentElement).getPropertyValue("--bg-primary").trim();
      // Simple heuristic: if the background starts with dark values, it's dark mode
      const isDark = bgPrimary.includes("#0") || bgPrimary.includes("#1") || bgPrimary.startsWith("rgb(1") || bgPrimary.startsWith("rgb(0");
      
      return {
        node: isDark ? "rgba(139, 92, 246, 0.55)" : "rgba(15, 23, 42, 0.25)",
        line: isDark ? "rgba(139, 92, 246, 0.25)" : "rgba(15, 23, 42, 0.1)",
      };
    };

    class Particle {
      constructor() {
        this.x = Math.random() * width;
        this.y = Math.random() * height;
        // Keep ambient movement extremely slow and subtle
        this.vx = prefersReducedMotion ? 0 : (Math.random() - 0.5) * 0.15;
        this.vy = prefersReducedMotion ? 0 : (Math.random() - 0.5) * 0.15;
        this.radius = Math.random() * 1.2 + 0.6;
        // 20% of nodes are slightly brighter/prominent to create depth
        this.depthMultiplier = Math.random() > 0.8 ? 1.6 : 0.7;
      }

      update() {
        this.x += this.vx;
        this.y += this.vy;

        // Wrap around screen
        if (this.x < 0) this.x = width;
        if (this.x > width) this.x = 0;
        if (this.y < 0) this.y = height;
        if (this.y > height) this.y = 0;
      }

      draw(offsetX, offsetY, colors) {
        ctx.beginPath();
        ctx.arc(this.x + offsetX, this.y + offsetY, this.radius, 0, Math.PI * 2);
        ctx.globalAlpha = this.depthMultiplier;
        ctx.fillStyle = colors.node;
        ctx.fill();
        ctx.globalAlpha = 1.0;
      }
    }

    const init = () => {
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = width;
      canvas.height = height;
      particles = [];
      const count = getParticleCount();
      for (let i = 0; i < count; i++) {
        particles.push(new Particle());
      }
    };

    const draw = () => {
      ctx.clearRect(0, 0, width, height);
      const colors = getColors();
      
      // Calculate parallax offset based on smooth spring values
      let offsetX = 0;
      let offsetY = 0;
      
      if (!prefersReducedMotion && !isTouch) {
        const sx = smoothX.get();
        const sy = smoothY.get();
        // Shift up to 40px based on mouse position from center
        offsetX = ((sx / width) - 0.5) * 80;
        offsetY = ((sy / height) - 0.5) * 80;
      }

      // Update & Draw particles
      particles.forEach((p) => {
        p.update();
        p.draw(offsetX, offsetY, colors);
      });

      // Draw connections
      const connectDistance = 140;
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const distance = Math.sqrt(dx * dx + dy * dy);

          if (distance < connectDistance) {
            ctx.beginPath();
            ctx.moveTo(particles[i].x + offsetX, particles[i].y + offsetY);
            ctx.lineTo(particles[j].x + offsetX, particles[j].y + offsetY);
            
            // Fade out opacity as distance increases
            const opacity = 1 - (distance / connectDistance);
            ctx.globalAlpha = opacity;
            ctx.strokeStyle = colors.line;
            ctx.lineWidth = 1;
            ctx.stroke();
            ctx.globalAlpha = 1.0;
          }
        }
      }

      animationFrameId = requestAnimationFrame(draw);
    };

    const handleResize = () => {
      init();
    };

    const handleMouseMove = (e) => {
      if (prefersReducedMotion || isTouch) return;
      mouseX.set(e.clientX);
      mouseY.set(e.clientY);
    };

    window.addEventListener("resize", handleResize);
    window.addEventListener("mousemove", handleMouseMove);

    init();
    draw();

    return () => {
      window.removeEventListener("resize", handleResize);
      window.removeEventListener("mousemove", handleMouseMove);
      cancelAnimationFrame(animationFrameId);
    };
  }, [mouseX, mouseY, smoothX, smoothY]);

  return (
    <div className="about-background-wrapper">
      <canvas ref={canvasRef} className="about-background-canvas" />
    </div>
  );
}
