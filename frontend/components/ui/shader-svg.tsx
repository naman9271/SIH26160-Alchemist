"use client";

import { MeshGradient } from "@paper-design/shaders-react";
import { motion } from "framer-motion";
import { useEffect, useRef, useState } from "react";

const colors = ["#5eead4", "#38bdf8", "#0f766e", "#0f172a", "#020617"];

export function MeshGradientSVG() {
  const artworkRef = useRef<SVGSVGElement>(null);
  const [eyeOffset, setEyeOffset] = useState({ x: 0, y: 0 });

  useEffect(() => {
    const handleMouseMove = (event: MouseEvent) => {
      const rect = artworkRef.current?.getBoundingClientRect();
      if (!rect) return;

      const x = (event.clientX - (rect.left + rect.width / 2)) * 0.08;
      const y = (event.clientY - (rect.top + rect.height / 2)) * 0.08;
      setEyeOffset({ x: Math.max(-8, Math.min(8, x)), y: Math.max(-8, Math.min(8, y)) });
    };

    window.addEventListener("mousemove", handleMouseMove);
    return () => window.removeEventListener("mousemove", handleMouseMove);
  }, []);

  return (
    <motion.div
      className="relative mx-auto w-full max-w-[22rem] p-5 sm:max-w-sm sm:p-8"
      animate={{ y: [0, -8, 0], scaleY: [1, 1.04, 1] }}
      transition={{ duration: 2.8, repeat: Number.POSITIVE_INFINITY, ease: "easeInOut" }}
      style={{ transformOrigin: "top center" }}
    >
      <svg ref={artworkRef} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 231 289" className="h-auto w-full text-slate-950" aria-label="Animated Alchemist signal">
        <defs>
          <clipPath id="alchemist-shape-clip">
            <path d="M230.809 115.385V249.411C230.809 269.923 214.985 287.282 194.495 288.411C184.544 288.949 175.364 285.718 168.26 280C159.746 273.154 147.769 273.461 139.178 280.23C132.638 285.384 124.381 288.462 115.379 288.462C106.377 288.462 98.1451 285.384 91.6055 280.23C82.912 273.385 70.9353 273.385 62.2415 280.23C55.7532 285.334 47.598 288.411 38.7246 288.462C17.4132 288.615 0 270.667 0 249.359V115.385C0 51.6667 51.6756 0 115.404 0C179.134 0 230.809 51.6667 230.809 115.385Z" />
          </clipPath>
        </defs>
        <foreignObject width="231" height="289" clipPath="url(#alchemist-shape-clip)">
          <div className="h-full w-full"><MeshGradient colors={colors} className="h-full w-full" speed={1} /></div>
        </foreignObject>
        <path d="M230.809 115.385V249.411C230.809 269.923 214.985 287.282 194.495 288.411C184.544 288.949 175.364 285.718 168.26 280C159.746 273.154 147.769 273.461 139.178 280.23C132.638 285.384 124.381 288.462 115.379 288.462C106.377 288.462 98.1451 285.384 91.6055 280.23C82.912 273.385 70.9353 273.385 62.2415 280.23C55.7532 285.334 47.598 288.411 38.7246 288.462C17.4132 288.615 0 270.667 0 249.359V115.385C0 51.6667 51.6756 0 115.404 0C179.134 0 230.809 51.6667 230.809 115.385Z" fill="none" stroke="rgba(153,246,228,.75)" strokeWidth="1.5" />
        <motion.ellipse rx="20" ry="30" fill="currentColor" animate={{ cx: 80 + eyeOffset.x, cy: 120 + eyeOffset.y, ry: [30, 30, 3, 30, 30] }} transition={{ cx: { type: "spring", stiffness: 150, damping: 15 }, cy: { type: "spring", stiffness: 150, damping: 15 }, ry: { duration: 3, repeat: Number.POSITIVE_INFINITY, times: [0, 0.88, 0.93, 0.98, 1] } }} />
        <motion.ellipse rx="20" ry="30" fill="currentColor" animate={{ cx: 150 + eyeOffset.x, cy: 120 + eyeOffset.y, ry: [30, 30, 3, 30, 30] }} transition={{ cx: { type: "spring", stiffness: 150, damping: 15 }, cy: { type: "spring", stiffness: 150, damping: 15 }, ry: { duration: 3, repeat: Number.POSITIVE_INFINITY, times: [0, 0.88, 0.93, 0.98, 1] } }} />
      </svg>
    </motion.div>
  );
}
