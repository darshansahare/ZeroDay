import React, { useState } from 'react';

/**
 * BlueTeamMascot
 * 
 * Reusable, cute, premium-quality Blue Team robot mascot for ZeroDay Arena.
 * Features rounded geometric forms, oversized head, expressive warm sensor eyes,
 * and the ZeroDay Arena Blue Team palette:
 * - Primary shell: cyber cobalt-blue #3B82F6 & soft azure #4E89B8
 * - Dark shell details: midnight navy #0C1829 & #111D33
 * - Secondary surfaces: dark titanium #1E293B
 * - Eye details: warm off-white / ice-blue #E0F2FE
 * - Visor: deep obsidian #0A1120
 * 
 * Hover interaction:
 * - Raises its left hand to wave hello
 * - A message box pops up: "Hi! I'm blue team agent"
 * 
 * Performs gentle vertical floating up and down; respects prefers-reduced-motion.
 */
export default function BlueTeamMascot({ size = 80, className = '' }) {
  const [isHovered, setIsHovered] = useState(false);

  // Maintain 60:64 aspect ratio
  const height = Math.round((size * 64) / 60);

  return (
    <div
      className={`blue-mascot-wrapper ${className}`}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      onFocus={() => setIsHovered(true)}
      onBlur={() => setIsHovered(false)}
      tabIndex={0}
      role="region"
      aria-label="ZeroDay Arena Blue Team Mascot"
    >
      {/* Speech message box popup on hover */}
      <div
        className={`blue-mascot-speech-bubble font-onest ${isHovered ? 'bubble-visible' : ''}`}
        role="status"
        aria-live="polite"
      >
        <span>Hi! I'm blue team agent</span>
        <div className="blue-bubble-tail" aria-hidden="true" />
      </div>

      <div className="blue-mascot-floating">
        <svg
          width={size}
          height={height}
          viewBox="0 0 60 64"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          aria-hidden="true"
          className="blue-mascot-svg"
        >
          {/* Internal Ground Contact Shadow */}
          <ellipse cx="30" cy="61" rx="18" ry="2.8" fill="#000000" opacity="0.35" />

          {/* Articulated Antenna */}
          <path
            d="M30 15 Q30 7 27 3.5"
            stroke="#0C1829"
            strokeWidth="2.6"
            strokeLinecap="round"
            fill="none"
          />
          <path
            d="M30 15 Q30 7 27 3.5"
            stroke="#38BDF8"
            strokeWidth="1.3"
            strokeLinecap="round"
            fill="none"
          />
          <circle cx="27" cy="3.5" r="3" fill="#38BDF8" stroke="#0C1829" strokeWidth="0.8" />
          <circle cx="27" cy="3.5" r="1" fill="#FFFFFF" />

          {/* Outer Hull Outline (Midnight Navy Frame) */}
          <rect
            x="10"
            y="15"
            width="40"
            height="40"
            rx="14"
            fill="#0C1829"
          />

          {/* Main Monocoque Hull (Cyber Cobalt-Blue #3B82F6) */}
          <rect
            x="11"
            y="16"
            width="38"
            height="38"
            rx="13"
            fill="#3B82F6"
          />

          {/* Soft Lower Torso Shading */}
          <path
            d="M12 41 C12 50 18 54 30 54 C42 54 48 50 48 41 Z"
            fill="#2563EB"
          />

          {/* Deep Navy Accent Belt */}
          <rect x="16" y="44" width="28" height="2.2" rx="1.1" fill="#1E3A8A" />

          {/* Dark Recessed Visor Plate */}
          <rect
            x="15"
            y="20"
            width="30"
            height="19"
            rx="6.5"
            fill="#0A1120"
            stroke="#1E293B"
            strokeWidth="0.9"
          />

          {/* Subtle Cyan Blush Dots */}
          <circle cx="18" cy="31" r="1.4" fill="#38BDF8" opacity="0.45" />
          <circle cx="42" cy="31" r="1.4" fill="#38BDF8" opacity="0.45" />

          {/* Left Sensor Eye (Warm Off-White / Soft Ice #E0F2FE) */}
          <circle cx="22.5" cy="28.5" r="3.2" fill="#E0F2FE" />
          <circle cx="22.5" cy="28.5" r="1.6" fill="#0A1120" />
          <circle cx="22" cy="27.7" r="0.8" fill="#FFFFFF" />

          {/* Right Sensor Eye */}
          <circle cx="37.5" cy="28.5" r="3.2" fill="#E0F2FE" />
          <circle cx="37.5" cy="28.5" r="1.6" fill="#0A1120" />
          <circle cx="37" cy="27.7" r="0.8" fill="#FFFFFF" />

          {/* Expressive Gentle Mouth */}
          <path
            d={isHovered ? "M27.5 34 Q30 37.5 32.5 34" : "M28.5 34.5 Q30 36 31.5 34.5"}
            stroke="#E0F2FE"
            strokeWidth="1.1"
            strokeLinecap="round"
            fill="none"
          />

          {/* Left Arm: Resting vs. Raised Waving Hand on Hover */}
          {isHovered ? (
            <g className="mascot-waving-arm-left">
              <path
                d="M11 32 Q5 24 7 17"
                stroke="#0C1829"
                strokeWidth="3.2"
                strokeLinecap="round"
                fill="none"
              />
              <path
                d="M11 32 Q5 24 7 17"
                stroke="#38BDF8"
                strokeWidth="1.8"
                strokeLinecap="round"
                fill="none"
              />
              {/* Hand Palm Highlight */}
              <circle cx="7" cy="17" r="1.4" fill="#38BDF8" />
            </g>
          ) : (
            <g className="mascot-resting-arm-left">
              <path
                d="M11 32 Q6 37 8 43"
                stroke="#0C1829"
                strokeWidth="3.2"
                strokeLinecap="round"
                fill="none"
              />
              <path
                d="M11 32 Q6 37 8 43"
                stroke="#3B82F6"
                strokeWidth="1.8"
                strokeLinecap="round"
                fill="none"
              />
            </g>
          )}

          {/* Right Arm (Resting) */}
          <path
            d="M49 32 Q54 37 52 43"
            stroke="#0C1829"
            strokeWidth="3.2"
            strokeLinecap="round"
            fill="none"
          />
          <path
            d="M49 32 Q54 37 52 43"
            stroke="#3B82F6"
            strokeWidth="1.8"
            strokeLinecap="round"
            fill="none"
          />

          {/* Tiny Treaded Feet (Graphite / Dark Titanium #1E293B) */}
          <rect x="16" y="52" width="7" height="4.5" rx="2" fill="#0C1829" />
          <rect x="17" y="53" width="5" height="2.5" rx="1.2" fill="#1E293B" />

          <rect x="37" y="52" width="7" height="4.5" rx="2" fill="#0C1829" />
          <rect x="38" y="53" width="5" height="2.5" rx="1.2" fill="#1E293B" />
        </svg>
      </div>

      {/* External Ground Shadow below floating mascot */}
      <div className="blue-mascot-shadow" aria-hidden="true" />
    </div>
  );
}

export { BlueTeamMascot };
