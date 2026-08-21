import { useEffect } from "react";
import { animate, useMotionValue, useTransform, motion } from "framer-motion";

/** Smoothly tweens to `value`, rendering with fixed decimals + optional suffix. */
export function AnimatedNumber({
  value, decimals = 0, suffix = "",
}: { value: number; decimals?: number; suffix?: string }) {
  const mv = useMotionValue(0);
  const text = useTransform(mv, (v) => v.toFixed(decimals) + suffix);
  useEffect(() => {
    const controls = animate(mv, value, { duration: 0.7, ease: [0.16, 1, 0.3, 1] });
    return controls.stop;
  }, [value, mv]);
  return <motion.span>{text}</motion.span>;
}
