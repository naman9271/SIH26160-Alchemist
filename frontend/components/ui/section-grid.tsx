type SectionGridProps = {
  opacity?: number;
};

/** A subtle structural grid for non-hero landing sections. */
export function SectionGrid({ opacity = 0.22 }: SectionGridProps) {
  return (
    <div
      aria-hidden="true"
      className="pointer-events-none absolute inset-0 bg-[linear-gradient(rgba(94,234,212,.16)_1px,transparent_1px),linear-gradient(90deg,rgba(94,234,212,.16)_1px,transparent_1px)] [background-size:42px_42px]"
      style={{ opacity }}
    />
  );
}
