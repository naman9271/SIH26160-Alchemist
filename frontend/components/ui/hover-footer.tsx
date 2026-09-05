"use client";

import { useEffect, useId, useRef, useState } from "react";
import { motion } from "framer-motion";

type TextHoverEffectProps = {
  text: string;
  duration?: number;
  className?: string;
};

export function TextHoverEffect({ text, duration = 0, className = "" }: TextHoverEffectProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const maskId = useId();
  const gradientId = useId();
  const [cursor, setCursor] = useState({ x: 0, y: 0 });
  const [hovered, setHovered] = useState(false);
  const [maskPosition, setMaskPosition] = useState({ cx: "50%", cy: "50%" });

  useEffect(() => {
    if (!svgRef.current) return;

    const svgRect = svgRef.current.getBoundingClientRect();
    const cxPercentage = ((cursor.x - svgRect.left) / svgRect.width) * 100;
    const cyPercentage = ((cursor.y - svgRect.top) / svgRect.height) * 100;

    setMaskPosition({
      cx: `${cxPercentage}%`,
      cy: `${cyPercentage}%`,
    });
  }, [cursor]);

  return (
    <svg
      ref={svgRef}
      width="100%"
      height="100%"
      viewBox="0 0 300 100"
      xmlns="http://www.w3.org/2000/svg"
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      onMouseMove={(event) => setCursor({ x: event.clientX, y: event.clientY })}
      className={`select-none uppercase ${className}`}
      aria-hidden="true"
    >
      <defs>
        <linearGradient id={gradientId} gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#99f6e4" />
          <stop offset="45%" stopColor="#5eead4" />
          <stop offset="100%" stopColor="#7dd3fc" />
        </linearGradient>
        <motion.radialGradient
          id={maskId}
          gradientUnits="userSpaceOnUse"
          r="22%"
          initial={{ cx: "50%", cy: "50%" }}
          animate={maskPosition}
          transition={{ duration, ease: "easeOut" }}
        >
          <stop offset="0%" stopColor="white" />
          <stop offset="100%" stopColor="black" />
        </motion.radialGradient>
        <mask id={`${maskId}-mask`}>
          <rect x="0" y="0" width="100%" height="100%" fill={`url(#${maskId})`} />
        </mask>
      </defs>

      <text
        x="50%"
        y="50%"
        textAnchor="middle"
        dominantBaseline="middle"
        strokeWidth="0.35"
        className="fill-transparent stroke-white/15 text-6xl font-bold tracking-[.08em]"
        style={{ opacity: hovered ? 0.75 : 0.35 }}
      >
        {text}
      </text>
      <motion.text
        x="50%"
        y="50%"
        textAnchor="middle"
        dominantBaseline="middle"
        strokeWidth="0.35"
        className="fill-transparent stroke-teal-100/45 text-6xl font-bold tracking-[.08em]"
        initial={{ strokeDashoffset: 1000, strokeDasharray: 1000 }}
        animate={{ strokeDashoffset: 0, strokeDasharray: 1000 }}
        transition={{ duration: 4, ease: "easeInOut" }}
      >
        {text}
      </motion.text>
      <text
        x="50%"
        y="50%"
        textAnchor="middle"
        dominantBaseline="middle"
        stroke={`url(#${gradientId})`}
        strokeWidth="0.45"
        mask={`url(#${maskId}-mask)`}
        className="fill-transparent text-6xl font-bold tracking-[.08em]"
      >
        {text}
      </text>
    </svg>
  );
}

export function FooterBackgroundGradient() {
  return (
    <div
      className="absolute inset-0 z-0"
      style={{
        background:
          "radial-gradient(110% 100% at 50% 0%, rgba(94,234,212,.14) 0%, rgba(8,11,18,.18) 42%, rgba(0,0,0,.95) 100%)",
      }}
    />
  );
}
