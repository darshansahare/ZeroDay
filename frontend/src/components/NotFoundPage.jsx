import React, { useEffect } from 'react';
import { ArrowRight } from 'lucide-react';
import RedTeamMascot from './RedTeamMascot';

/**
 * Custom Minimalist 404 Not Found Page for ZeroDay
 * Clean, centered, distraction-free:
 * - 404 centered in the viewport
 * - Red Team Mascot sighing directly to the left of 404 (with off-white *sigh...* text, no message box)
 * - Headline & Description
 * - Centered "Back to ZeroDay" action with no border or box
 */
export default function NotFoundPage({ onNavigateHome }) {
  // Update document title to exact string without em dash
  useEffect(() => {
    const previousTitle = document.title;
    document.title = '404 Page Not Found';
    return () => {
      document.title = previousTitle;
    };
  }, []);

  return (
    <div className="not-found-canvas font-onest">
      {/* Background Engineering Grid Pattern */}
      <div className="not-found-grid-pattern" aria-hidden="true" />

      <main
        className="not-found-container"
        role="main"
        aria-labelledby="not-found-title"
        aria-describedby="not-found-desc"
      >
        {/* Centered 404 with Red Mascot anchored directly to its left */}
        <div className="not-found-code-wrapper" aria-hidden="true">
          <div className="not-found-mascot-left">
            <RedTeamMascot
              size={86}
              mood="sigh"
              bubbleText="*sigh...*"
              showBubbleAlways={true}
            />
          </div>

          <span className="not-found-number font-oxanium">
            <span>4</span>
            <span className="not-found-zero">0</span>
            <span>4</span>
          </span>
        </div>

        {/* Headline & Description */}
        <div className="not-found-text-block">
          <h1 id="not-found-title" className="not-found-title font-oxanium">
            This endpoint doesn't exist.
          </h1>
          <p id="not-found-desc" className="not-found-desc font-onest">
            The resource you're looking for isn't available at this address.
            It may have moved, or the route may be incorrect.
          </p>
        </div>

        {/* Centered Back to ZeroDay CTA without border or box */}
        <div className="not-found-actions">
          <button
            type="button"
            onClick={onNavigateHome}
            className="btn-404-link font-onest"
            id="btn-back-to-zeroday"
            aria-label="Return to ZeroDay home overview"
          >
            <span>Back to ZeroDay</span>
            <ArrowRight size={16} aria-hidden="true" className="btn-404-arrow" />
          </button>
        </div>
      </main>
    </div>
  );
}
