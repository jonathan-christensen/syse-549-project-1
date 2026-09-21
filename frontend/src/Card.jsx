export default function Card({ children }) {
  return (
    <div className="page">
      <div className="card">
        <div className="header">
          <span className="logo-badge">549</span>
          <span className="logo-text">SYSE 549 Drive</span>
        </div>
        <div className="content">{children}</div>
      </div>
    </div>
  );
}
