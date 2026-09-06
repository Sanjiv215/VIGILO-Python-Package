import React from 'react';
import DOMPurify from 'dompurify';

interface CleanBioProps {
  safeText: string;
  rawUntrusted: string;
}

export const CleanBio: React.FC<CleanBioProps> = ({ safeText, rawUntrusted }) => {
  return (
    <div className="bio-container">
      {/* Safe 1: standard React JSX rendering auto-escapes */}
      <p>{safeText}</p>

      {/* Safe 2: static literal string in dangerouslySetInnerHTML */}
      <div dangerouslySetInnerHTML={{ __html: '<strong>Verified Safe</strong>' }} />

      {/* Safe 3: sanitized dynamic content via DOMPurify */}
      <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(rawUntrusted) }} />
    </div>
  );
};
