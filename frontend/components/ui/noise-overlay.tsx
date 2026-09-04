import type { CSSProperties } from "react";

type NoiseOverlayProps = {
  opacity?: number;
  blendMode?: CSSProperties["mixBlendMode"];
  className?: string;
  position?: "fixed" | "absolute";
  layer?: "behind" | "over";
};

/**
 * SVG grain with no image asset, canvas, or animation. Use `absolute` when
 * the texture should be limited to a page region.
 */
export function NoiseOverlay({
  opacity = 0.22,
  blendMode = "normal",
  className = "",
  position = "fixed",
  layer = "behind",
}: NoiseOverlayProps) {
  return (
    <div
      aria-hidden="true"
      className={`pointer-events-none inset-0 ${layer === "over" ? "z-20" : "z-[1]"} h-full w-full ${position} ${className}`}
      style={{ opacity, mixBlendMode: blendMode }}
    >
      <svg
        className="h-full w-full"
        xmlns="http://www.w3.org/2000/svg"
        preserveAspectRatio="none"
      >
        <filter id="landing-noise-filter">
          <feTurbulence
            type="fractalNoise"
            baseFrequency="0.9"
            numOctaves="5"
            stitchTiles="stitch"
          />
          <feColorMatrix type="saturate" values="0" />
        </filter>
        <rect width="100%" height="100%" filter="url(#landing-noise-filter)" />
      </svg>
    </div>
  );
}
