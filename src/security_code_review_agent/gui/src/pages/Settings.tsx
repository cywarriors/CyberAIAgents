export default function Settings() {
  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Settings</h1>
      <div className="bg-gray-800 rounded-lg p-6 max-w-lg">
        <p className="text-gray-400 text-sm">
          Configure via environment variables (CODE_REVIEW_* prefix).
        </p>
        <ul className="mt-4 text-sm text-gray-300 space-y-1">
          <li><span className="font-mono text-indigo-300">CODE_REVIEW_VCS_API_URL</span> — VCS endpoint</li>
          <li><span className="font-mono text-indigo-300">CODE_REVIEW_POLICY_BLOCK_SEVERITY</span> — critical/high/medium</li>
          <li><span className="font-mono text-indigo-300">CODE_REVIEW_SUPPORTED_LANGUAGES</span> — comma-separated</li>
          <li><span className="font-mono text-indigo-300">CODE_REVIEW_NVD_API_URL</span> — NVD database endpoint</li>
        </ul>
      </div>
    </div>
  );
}
