import React, { useState } from 'react';

/**
 * RedTeamMascot
 * 
 * Reusable, cute, premium-quality Red Team robot mascot for ZeroDay Arena.
 * Features rounded geometric forms, oversized head, expressive warm off-white sensor eyes,
 * and the ZeroDay Arena Red Team palette:
 * - Primary shell: muted crimson #D65A52
 * - Dark shell details: deep burgundy #492326 & #201416
 * - Secondary surfaces: graphite #292D30
 * - Eye details: warm off-white #F2F2F0
 * - Small metallic details: brushed steel
 * 
 * Moods:
 * - 'default': waves on hover with "Hi! I'm red team agent"
 * - 'sigh': drooping antenna, sad/sleepy eyes, soft sigh mouth, sigh speech bubble "*sigh...*"
 */
export default function RedTeamMascot({
  size = 80,
  className = '',
  mood = 'default',
  bubbleText,
  showBubbleAlways = false,
}) {
  const [isHovered, setIsHovered] = useState(false);
  const isSigh = mood === 'sigh';

  // Maintain 60:64 aspect ratio
  const height = Math.round((size * 64) / 60);

  const displayBubbleText =
    bubbleText || (isSigh ? '*sigh...*' : "Hi! I'm red team agent");
  const isBubbleVisible = showBubbleAlways || isHovered;

  return (
    <div
      className={`red-mascot-wrapper ${isSigh ? 'mascot-sigh-mood' : ''} ${className}`}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      onFocus={() => setIsHovered(true)}
      onBlur={() => setIsHovered(false)}
      tabIndex={0}
      role="region"
      aria-label="ZeroDay Arena Red Team Mascot"
    >
      {/* Speech message box popup on hover or always in sigh mood */}
      <div
        className={`mascot-speech-bubble font-onest ${isBubbleVisible ? 'bubble-visible' : ''} ${isSigh ? 'bubble-sigh' : ''}`}
        role="status"
        aria-live="polite"
      >
        <span>{displayBubbleText}</span>
        <div className="bubble-tail" aria-hidden="true" />
      </div>

      <div className="red-mascot-floating">
        <svg
          width={size}
          height={height}
          viewBox="0 0 60 64"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          aria-hidden="true"
          className="red-mascot-svg"
        >
          {/* Internal Ground Contact Shadow */}
          <ellipse cx="30" cy="61" rx="18" ry="2.8" fill="#000000" opacity="0.35" />

          {/* Articulated Antenna (Drooping in sigh mood, erect in default) */}
          {isSigh ? (
            <g className="antenna-sigh">
              <path
                d="M30 15 Q26 12 21 13"
                stroke="#201416"
                strokeWidth="2.6"
                strokeLinecap="round"
                fill="none"
              />
              <path
                d="M30 15 Q26 12 21 13"
                stroke="#D65A52"
                strokeWidth="1.3"
                strokeLinecap="round"
                fill="none"
              />
              <circle cx="21" cy="13" r="3" fill="#D65A52" stroke="#201416" strokeWidth="0.8" />
              <circle cx="21" cy="13" r="1" fill="#FFFFFF" />
            </g>
          ) : (
            <g className="antenna-default">
              <path
                d="M30 15 Q30 7 33 3.5"
                stroke="#201416"
                strokeWidth="2.6"
                strokeLinecap="round"
                fill="none"
              />
              <path
                d="M30 15 Q30 7 33 3.5"
                stroke="#D65A52"
                strokeWidth="1.3"
                strokeLinecap="round"
                fill="none"
              />
              <circle cx="33" cy="3.5" r="3" fill="#D65A52" stroke="#201416" strokeWidth="0.8" />
              <circle cx="33" cy="3.5" r="1" fill="#FFFFFF" />
            </g>
          )}

          {/* Outer Hull Outline (Deep Burgundy / Dark Border) */}
          <rect
            x="10"
            y="15"
            width="40"
            height="40"
            rx="14"
            fill="#201416"
          />

          {/* Main Monocoque Hull (Muted Crimson #D65A52) */}
          <rect
            x="11"
            y="16"
            width="38"
            height="38"
            rx="13"
            fill="#D65A52"
          />

          {/* Soft Lower Torso Shading */}
          <path
            d="M12 41 C12 50 18 54 30 54 C42 54 48 50 48 41 Z"
            fill="#B0443C"
          />

          {/* Deep Burgundy Accent Belt */}
          <rect x="16" y="44" width="28" height="2.2" rx="1.1" fill="#492326" />

          {/* Dark Recessed Visor Plate */}
          <rect
            x="15"
            y="20"
            width="30"
            height="19"
            rx="6.5"
            fill="#181416"
            stroke="#292D30"
            strokeWidth="0.9"
          />

          {/* Subtle Blush Dots */}
          <circle cx="18" cy="31" r="1.4" fill="#EF9F73" opacity="0.35" />
          <circle cx="42" cy="31" r="1.4" fill="#EF9F73" opacity="0.35" />

          {/* Eyes (Sighing sleepy eyelids vs. wide sensor eyes) */}
          {isSigh ? (
            <g className="eyes-sigh">
              {/* Left Eye */}
              <circle cx="22.5" cy="29" r="3.2" fill="#F2F2F0" />
              <circle cx="22.5" cy="29.2" r="1.6" fill="#181416" />
              <circle cx="22" cy="28.7" r="0.8" fill="#FFFFFF" />
              {/* Left Drooping Eyelid */}
              <path
                d="M19.2 28 Q22.5 30 25.8 28"
                stroke="#181416"
                strokeWidth="1.8"
                strokeLinecap="round"
                fill="none"
              />

              {/* Right Eye */}
              <circle cx="37.5" cy="29" r="3.2" fill="#F2F2F0" />
              <circle cx="37.5" cy="29.2" r="1.6" fill="#181416" />
              <circle cx="37" cy="28.7" r="0.8" fill="#FFFFFF" />
              {/* Right Drooping Eyelid */}
              <path
                d="M34.2 28 Q37.5 30 40.8 28"
                stroke="#181416"
                strokeWidth="1.8"
                strokeLinecap="round"
                fill="none"
              />
            </g>
          ) : (
            <g className="eyes-default">
              {/* Left Sensor Eye (Warm Off-White #F2F2F0) */}
              <circle cx="22.5" cy="28.5" r="3.2" fill="#F2F2F0" />
              <circle cx="22.5" cy="28.5" r="1.6" fill="#181416" />
              <circle cx="22" cy="27.7" r="0.8" fill="#FFFFFF" />

              {/* Right Sensor Eye */}
              <circle cx="37.5" cy="28.5" r="3.2" fill="#F2F2F0" />
              <circle cx="37.5" cy="28.5" r="1.6" fill="#181416" />
              <circle cx="37" cy="27.7" r="0.8" fill="#FFFFFF" />
            </g>
          )}

          {/* Expressive Mouth (Sigh downward curve + breath puff vs. neutral/happy) */}
          {isSigh ? (
            <g className="mouth-sigh">
              <path
                d="M28.5 35.5 Q30 34 31.5 35.5"
                stroke="#F2F2F0"
                strokeWidth="1.1"
                strokeLinecap="round"
                fill="none"
              />
              {/* Small breath sigh puff */}
              <path
                d="M34 35.5 Q36.5 34 38.5 35.5"
                stroke="rgba(242, 242, 240, 0.45)"
                strokeWidth="0.9"
                strokeLinecap="round"
                fill="none"
              />
            </g>
          ) : (
            <path
              d={isHovered ? "M27.5 34 Q30 37.5 32.5 34" : "M28.5 34.5 Q30 36 31.5 34.5"}
              stroke="#F2F2F0"
              strokeWidth="1.1"
              strokeLinecap="round"
              fill="none"
            />
          )}

          {/* Left Arm (Resting) */}
          <path
            d="M11 32 Q6 37 8 43"
            stroke="#201416"
            strokeWidth="3.2"
            strokeLinecap="round"
            fill="none"
          />
          <path
            d="M11 32 Q6 37 8 43"
            stroke="#D65A52"
            strokeWidth="1.8"
            strokeLinecap="round"
            fill="none"
          />

          {/* Right Arm: Resting vs. Raised Waving Hand (Only waves in default mode when hovered) */}
          {!isSigh && isHovered ? (
            <g className="mascot-waving-arm">
              <path
                d="M49 32 Q55 24 53 17"
                stroke="#201416"
                strokeWidth="3.2"
                strokeLinecap="round"
                fill="none"
              />
              <path
                d="M49 32 Q55 24 53 17"
                stroke="#D65A52"
                strokeWidth="1.8"
                strokeLinecap="round"
                fill="none"
              />
              {/* Hand Palm Highlight */}
              <circle cx="53" cy="17" r="1.4" fill="#EF9F73" />
            </g>
          ) : (
            <g className="mascot-resting-arm">
              <path
                d="M49 32 Q54 37 52 43"
                stroke="#201416"
                strokeWidth="3.2"
                strokeLinecap="round"
                fill="none"
              />
              <path
                d="M49 32 Q54 37 52 43"
                stroke="#D65A52"
                strokeWidth="1.8"
                strokeLinecap="round"
                fill="none"
              />
            </g>
          )}

          {/* Tiny Treaded Feet (Graphite #292D30) */}
          <rect x="16" y="52" width="7" height="4.5" rx="2" fill="#201416" />
          <rect x="17" y="53" width="5" height="2.5" rx="1.2" fill="#292D30" />

          <rect x="37" y="52" width="7" height="4.5" rx="2" fill="#201416" />
          <rect x="38" y="53" width="5" height="2.5" rx="1.2" fill="#292D30" />
        </svg>
      </div>

      {/* External Ground Shadow below floating mascot */}
      <div className="red-mascot-shadow" aria-hidden="true" />
    </div>
  );
}

export { RedTeamMascot };
