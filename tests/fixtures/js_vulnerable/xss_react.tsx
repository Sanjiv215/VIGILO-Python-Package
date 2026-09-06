import React, { useState } from 'react';

interface UserProfileProps {
  userId: string;
  rawBio: string;
}

export const UserProfile: React.FC<UserProfileProps> = ({ userId, rawBio }) => {
  const [theme, setTheme] = useState<string>('dark');

  const renderLegacyBio = () => {
    const el = document.getElementById('legacy-bio-container');
    if (el) {
      // VIGILO-JS-001 finding: direct dynamic innerHTML assignment
      el.innerHTML = rawBio;
    }
  };

  return (
    <div className={`profile-container ${theme}`}>
      <h1>User #{userId}</h1>
      {/* VIGILO-JS-001 finding: React dangerouslySetInnerHTML with dynamic unescaped prop */}
      <div
        className="bio-section"
        dangerouslySetInnerHTML={{ __html: rawBio }}
      />
      <button onClick={renderLegacyBio}>Load Legacy View</button>
    </div>
  );
};
