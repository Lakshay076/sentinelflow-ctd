import React, { useRef, useState, useMemo, useEffect } from 'react';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import { OrbitControls, Html, Line, Grid } from '@react-three/drei';
import * as THREE from 'three';
import { Search, X, RotateCcw, Shield, Clock, AlertTriangle } from 'lucide-react';
import { formatAttackType } from '../utils';

// Hook to track data-theme on documentElement
function useCurrentTheme() {
  const [theme, setTheme] = useState(() => {
    if (typeof document !== 'undefined') {
      return document.documentElement.getAttribute('data-theme') || 'light';
    }
    return 'light';
  });

  useEffect(() => {
    const updateTheme = () => {
      const t = document.documentElement.getAttribute('data-theme') || 'light';
      setTheme(t);
    };
    const observer = new MutationObserver(updateTheme);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    return () => observer.disconnect();
  }, []);

  return theme;
}

// Format timestamp for tooltips and axis ticks
function formatTimestamp(epochSec) {
  if (!epochSec || isNaN(epochSec)) return 'Unknown';
  const d = new Date(epochSec * 1000);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatShortTime(epochSec) {
  if (!epochSec || isNaN(epochSec)) return '';
  const d = new Date(epochSec * 1000);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function formatDuration(sec) {
  if (sec == null || isNaN(sec)) return '< 1s';
  if (sec < 1) return '< 1s';
  if (sec < 60) return `${sec.toFixed(1)}s`;
  const m = Math.floor(sec / 60);
  const s = Math.round(sec % 60);
  return `${m}m ${s}s`;
}

// Single Incident 3D Node
const IncidentNode = ({ 
  alert, 
  position, 
  color, 
  geometryType, 
  baseRadius,
  isHovered, 
  isDimmed, 
  isSameSourceHighlighted,
  onPointerOver, 
  onPointerOut, 
  onClick 
}) => {
  const meshRef = useRef();
  const isActive = alert.status === 'ACTIVE';

  useFrame((state) => {
    if (!meshRef.current) return;

    if (!isDimmed) {
      // Gentle breathing pulse for active incidents only
      let targetScale = 1.0;
      if (isActive) {
        targetScale = 1.0 + Math.sin(state.clock.elapsedTime * 3) * 0.08;
      }
      if (isHovered) {
        targetScale = 1.35;
      } else if (isSameSourceHighlighted) {
        targetScale = 1.15;
      }
      meshRef.current.scale.lerp(new THREE.Vector3(targetScale, targetScale, targetScale), 0.18);
    }
  });

  const opacity = isDimmed ? 0.1 : (alert.status === 'RESOLVED' && !isHovered ? 0.75 : 1.0);
  const emissiveIntensity = isDimmed 
    ? 0 
    : (isHovered ? 2.2 : (isSameSourceHighlighted ? 1.4 : (isActive ? 1.1 : 0.35)));

  return (
    <group position={position}>
      {/* Drop-line connecting the node to the timeline floor */}
      <Line
        points={[[0, 0, 0], [0, -4 - position.y, 0]]}
        color={color}
        lineWidth={isHovered ? 2 : 1}
        opacity={isDimmed ? 0.04 : (isHovered ? 0.8 : 0.22)}
        transparent
      />

      {/* Floor beacon / footprint */}
      <mesh position={[0, -4 - position.y + 0.02, 0]} rotation={[-Math.PI / 2, 0, 0]}>
        {isActive ? (
          <ringGeometry args={[0.3, 0.6, 24]} />
        ) : (
          <circleGeometry args={[0.35, 20]} />
        )}
        <meshBasicMaterial 
          color={color} 
          transparent 
          opacity={isDimmed ? 0.03 : (isHovered ? 0.85 : (isActive ? 0.65 : 0.25))} 
        />
      </mesh>

      {/* Main 3D Geometry */}
      <mesh
        ref={meshRef}
        onPointerOver={(e) => {
          e.stopPropagation();
          onPointerOver(alert);
        }}
        onPointerOut={(e) => {
          e.stopPropagation();
          onPointerOut();
        }}
        onClick={(e) => {
          e.stopPropagation();
          onClick(alert);
        }}
        cursor="pointer"
      >
        {geometryType === 'sphere' && <sphereGeometry args={[baseRadius, 24, 24]} />}
        {geometryType === 'octahedron' && <octahedronGeometry args={[baseRadius * 1.05, 0]} />}
        {geometryType === 'icosahedron' && <icosahedronGeometry args={[baseRadius * 1.1, 0]} />}

        <meshStandardMaterial
          color={color}
          emissive={color}
          emissiveIntensity={emissiveIntensity}
          transparent
          opacity={opacity}
          wireframe={isDimmed}
          roughness={0.25}
          metalness={0.4}
        />
      </mesh>

      {/* Hover HTML Tooltip */}
      {isHovered && !isDimmed && (
        <Html distanceFactor={18} position={[0, 1.2, 0]} center zIndexRange={[100, 0]}>
          <div className="incident-3d-tooltip">
            <div className="incident-3d-tooltip-title">
              <strong style={{ color, fontSize: '13px' }}>
                {formatAttackType(alert.attack_type)}
              </strong>
              <span
                style={{
                  fontSize: '10px',
                  fontWeight: 700,
                  padding: '2px 6px',
                  borderRadius: '12px',
                  background: isActive ? 'var(--severity-critical-bg)' : 'var(--status-healthy-bg)',
                  color: isActive ? 'var(--severity-critical)' : 'var(--status-healthy)',
                  border: `1px solid ${isActive ? 'var(--severity-critical)' : 'var(--status-healthy)'}`
                }}
              >
                {isActive ? '● ACTIVE' : '○ RESOLVED'}
              </span>
            </div>

            <div className="incident-3d-tooltip-grid">
              <div><strong>Severity:</strong> {alert.severity}</div>
              <div><strong>Confidence:</strong> {Math.round((alert.confidence || 0) * 100)}%</div>
              <div><strong>Events:</strong> {alert.event_count || 1}</div>
              <div><strong>Duration:</strong> {formatDuration(alert.duration)}</div>
            </div>

            <div className="incident-3d-tooltip-meta">
              <div><strong>Source:</strong> <span style={{ fontFamily: 'var(--font-mono)' }}>{alert.source_ip || 'Unknown'}</span></div>
              {alert.dest_ip && (
                <div><strong>Destination:</strong> <span style={{ fontFamily: 'var(--font-mono)' }}>{alert.dest_ip}</span></div>
              )}
              <div style={{ color: 'var(--text-muted)', marginTop: '2px' }}>
                <strong>First Seen:</strong> {formatTimestamp(alert.first_seen)}
              </div>
              {alert.last_seen && alert.last_seen !== alert.first_seen && (
                <div style={{ color: 'var(--text-muted)' }}>
                  <strong>Last Seen:</strong> {formatTimestamp(alert.last_seen)}
                </div>
              )}
            </div>

            <div className="incident-3d-tooltip-prompt">
              Click to open investigation drawer →
            </div>
          </div>
        </Html>
      )}
    </group>
  );
};

// Automatic Camera Framing
const AutoFramer = ({ nodes, resetTrigger }) => {
  const { camera, controls } = useThree();

  useEffect(() => {
    if (!nodes || nodes.length === 0 || !controls) return;

    const box = new THREE.Box3();
    nodes.forEach((n) => box.expandByPoint(n.position));
    if (box.isEmpty()) return;

    const center = new THREE.Vector3();
    box.getCenter(center);

    const size = new THREE.Vector3();
    box.getSize(size);
    const maxDim = Math.max(size.x, size.y, size.z, 14);

    // Architectural perspective framing
    camera.position.set(center.x, center.y + maxDim * 0.7, center.z + maxDim * 1.55);
    controls.target.set(center.x, Math.max(center.y, 0), center.z);
    controls.update();
  }, [nodes, resetTrigger, camera, controls]);

  return null;
};

// Timeline Network and Guides
const TimelineNetwork = ({ 
  alerts, 
  onNodeClick, 
  searchQuery, 
  resetTrigger,
  theme
}) => {
  const [hoveredAlert, setHoveredAlert] = useState(null);

  const { 
    nodes, 
    sourceLines, 
    sourceLanes, 
    timeTicks,
    minTime,
    maxTime
  } = useMemo(() => {
    if (!alerts || alerts.length === 0) {
      return { nodes: [], sourceLines: [], sourceLanes: [], timeTicks: [], minTime: 0, maxTime: 0 };
    }

    const timestamps = alerts.map((a) => a.first_seen || 0);
    const minTime = Math.min(...timestamps);
    const maxTime = Math.max(...timestamps);
    const timeRange = maxTime - minTime || 1;

    const xSpan = 32; // Total X span
    const sources = [...new Set(alerts.map((a) => a.source_ip || 'Unknown'))].sort();
    const zSpan = sources.length > 1 ? Math.min(20, sources.length * 6) : 0;
    const zStep = sources.length > 1 ? zSpan / (sources.length - 1) : 0;

    // Source Lanes definition
    const lanes = sources.map((source, idx) => {
      const z = sources.length > 1 ? (idx * zStep) - (zSpan / 2) : 0;
      return { source, z };
    });

    // Generate Time Ticks
    const numTicks = 5;
    const ticks = [];
    for (let i = 0; i < numTicks; i++) {
      const tNorm = i / (numTicks - 1);
      const tickTime = minTime + (tNorm * timeRange);
      const x = (tNorm * xSpan) - (xSpan / 2);
      ticks.push({
        x,
        time: tickTime,
        label: formatShortTime(tickTime),
      });
    }

    // Map each alert to 3D node
    const mappedNodes = alerts.map((alert) => {
      // X = Chronological Time
      const tNorm = ((alert.first_seen || 0) - minTime) / timeRange;
      const x = (tNorm * xSpan) - (xSpan / 2);

      // Y = Severity + Confidence mapping
      const sevUpper = (alert.severity || '').toUpperCase();
      const isHigh = sevUpper === 'HIGH' || sevUpper === 'CRITICAL';
      const isMedium = sevUpper === 'MEDIUM';

      let baseSeverityY = -1.0; // Low
      let color = '#3b82f6';
      let geometryType = 'sphere';

      if (isHigh) {
        baseSeverityY = 6.5;
        color = '#ef4444';
        geometryType = 'icosahedron';
      } else if (isMedium) {
        baseSeverityY = 2.5;
        color = '#f59e0b';
        geometryType = 'octahedron';
      }

      const conf = alert.confidence || 0.5;
      const y = baseSeverityY + (conf * 1.5);

      // Z = Source Lane
      const sourceIndex = sources.indexOf(alert.source_ip || 'Unknown');
      const z = sources.length > 1 ? (sourceIndex * zStep) - (zSpan / 2) : 0;

      // Clamped radius based on event count
      const baseRadius = 0.45 + (Math.min(alert.event_count || 1, 60) / 60) * 0.4;

      // Filter matching
      let isDimmed = false;
      if (searchQuery && searchQuery.trim().length > 0) {
        const query = searchQuery.trim().toLowerCase();
        const matchesSource = (alert.source_ip || '').toLowerCase().includes(query);
        const matchesType = (alert.attack_type || '').toLowerCase().includes(query);
        isDimmed = !(matchesSource || matchesType);
      }

      return {
        alert,
        position: new THREE.Vector3(x, y, z),
        color,
        geometryType,
        baseRadius,
        isDimmed,
      };
    });

    // Chronological correlation lines between incidents with SAME source IP
    const bySource = {};
    mappedNodes.forEach((node) => {
      const src = node.alert.source_ip || 'Unknown';
      if (!bySource[src]) bySource[src] = [];
      bySource[src].push(node);
    });

    const lines = [];
    Object.entries(bySource).forEach(([src, srcNodes]) => {
      if (srcNodes.length < 2) return;
      srcNodes.sort((a, b) => (a.alert.first_seen || 0) - (b.alert.first_seen || 0));

      for (let i = 0; i < srcNodes.length - 1; i++) {
        lines.push({
          source: src,
          points: [srcNodes[i].position, srcNodes[i + 1].position],
          nodes: [srcNodes[i].alert.alert_id, srcNodes[i + 1].alert.alert_id],
        });
      }
    });

    return {
      nodes: mappedNodes,
      sourceLines: lines,
      sourceLanes: lanes,
      timeTicks: ticks,
      minTime,
      maxTime,
    };
  }, [alerts, searchQuery]);

  // Theme-specific colors
  const isDark = theme === 'dark';
  const gridLineColor = isDark ? '#2B2B32' : '#E5DDD2';
  const floorPlaneColor = isDark ? '#18181B' : '#F2ECE3';
  const axisGuideColor = isDark ? '#3E3E48' : '#D5CBBF';

  return (
    <group>
      <AutoFramer nodes={nodes} resetTrigger={resetTrigger} />

      {/* Subtle Visual Timeline Floor Plane */}
      <mesh position={[0, -4.02, 0]} rotation={[-Math.PI / 2, 0, 0]}>
        <planeGeometry args={[44, 30]} />
        <meshBasicMaterial color={floorPlaneColor} transparent opacity={isDark ? 0.65 : 0.5} />
      </mesh>

      {/* Floor Grid */}
      <Grid
        position={[0, -4.01, 0]}
        args={[44, 30]}
        cellSize={2}
        cellThickness={0.8}
        cellColor={gridLineColor}
        sectionSize={8}
        sectionThickness={1.2}
        sectionColor={axisGuideColor}
        fadeDistance={55}
        fadeStrength={1.2}
      />

      {/* ====================================================================
          X-AXIS (TIME) GUIDES & TICKS
          ==================================================================== */}
      {/* Front Floor Axis Rail */}
      <Line
        points={[[-17, -4, 15], [17, -4, 15]]}
        color={axisGuideColor}
        lineWidth={2}
      />

      {/* Time Tick Marks & Floor Intervals */}
      {timeTicks.map((tick, i) => (
        <group key={`tick-${i}`}>
          {/* Subtle transverse floor guide line */}
          <Line
            points={[[tick.x, -4, -13], [tick.x, -4, 15]]}
            color={axisGuideColor}
            lineWidth={1}
            opacity={0.25}
            transparent
          />
          {/* Time Tick Marker on Front Rail */}
          <Line
            points={[[tick.x, -4, 14.7], [tick.x, -4, 15.3]]}
            color={axisGuideColor}
            lineWidth={2}
          />
          {/* Formatted HTML Time Tick */}
          <Html position={[tick.x, -4.25, 15.2]} center distanceFactor={22}>
            <span className="incident-3d-tick-label">{tick.label}</span>
          </Html>
        </group>
      ))}

      {/* X Axis Title Label */}
      <Html position={[0, -4.75, 16.5]} center distanceFactor={22}>
        <span className="incident-3d-axis-title">TIME (CHRONOLOGICAL) →</span>
      </Html>

      {/* ====================================================================
          Y-AXIS (SEVERITY / CONFIDENCE) GUIDES
          ==================================================================== */}
      {/* Vertical Axis Pillar at Front-Left Corner */}
      <Line
        points={[[-18, -4, 15], [-18, 8.5, 15]]}
        color={axisGuideColor}
        lineWidth={2}
      />

      {/* Y Axis Level Ticks */}
      {[
        { label: 'HIGH', y: 7.2, color: '#ef4444' },
        { label: 'MED', y: 3.2, color: '#f59e0b' },
        { label: 'LOW', y: -0.3, color: '#3b82f6' },
      ].map((lvl, idx) => (
        <group key={`y-lvl-${idx}`}>
          <Line
            points={[[-18.5, lvl.y, 15], [-17.5, lvl.y, 15]]}
            color={lvl.color}
            lineWidth={2}
          />
          <Html position={[-19.5, lvl.y, 15]} center distanceFactor={22}>
            <span 
              className="incident-3d-tick-label"
              style={{ color: lvl.color, fontWeight: 700 }}
            >
              {lvl.label}
            </span>
          </Html>
        </group>
      ))}

      {/* Y Axis Title Label */}
      <Html position={[-18.5, 9.3, 15]} center distanceFactor={22}>
        <span className="incident-3d-axis-title">SEVERITY / CONFIDENCE ↑</span>
      </Html>

      {/* ====================================================================
          Z-AXIS (SOURCE LANES) GUIDES & LABELS
          ==================================================================== */}
      {sourceLanes.map((lane, idx) => {
        const isHoveredLane = hoveredAlert?.source_ip === lane.source;

        return (
          <group key={`lane-${idx}`}>
            {/* Lane Floor Track Line */}
            <Line
              points={[[-17, -4, lane.z], [17, -4, lane.z]]}
              color={isHoveredLane ? '#8b5cf6' : axisGuideColor}
              lineWidth={isHoveredLane ? 2.5 : 1}
              opacity={isHoveredLane ? 0.9 : 0.3}
              transparent
            />
            {/* Source IP Lane Label at Left Edge */}
            <Html position={[-18.5, -3.85, lane.z]} center distanceFactor={22}>
              <span className={`incident-3d-lane-label ${isHoveredLane ? 'highlighted' : ''}`}>
                {lane.source}
              </span>
            </Html>
          </group>
        );
      })}

      {/* Z Axis Title */}
      <Html position={[-18.5, -3.85, -14]} center distanceFactor={22}>
        <span className="incident-3d-axis-title">SOURCE LANES ↗</span>
      </Html>

      {/* ====================================================================
          SAME-SOURCE CHRONOLOGICAL CORRELATION LINES
          ==================================================================== */}
      {sourceLines.map((line, i) => {
        const isHighlighted =
          hoveredAlert && hoveredAlert.source_ip === line.source;

        return (
          <Line
            key={`src-line-${i}`}
            points={line.points}
            color={isHighlighted ? '#8b5cf6' : axisGuideColor}
            lineWidth={isHighlighted ? 3 : 1.5}
            opacity={isHighlighted ? 0.95 : 0.35}
            transparent
          />
        );
      })}

      {/* ====================================================================
          INCIDENT NODES
          ==================================================================== */}
      {nodes.map((node) => {
        const isHovered = hoveredAlert?.alert_id === node.alert.alert_id;
        const isSameSource =
          hoveredAlert &&
          hoveredAlert.source_ip === node.alert.source_ip &&
          !isHovered;

        return (
          <IncidentNode
            key={node.alert.alert_id}
            alert={node.alert}
            position={node.position}
            color={node.color}
            geometryType={node.geometryType}
            baseRadius={node.baseRadius}
            isHovered={isHovered}
            isDimmed={node.isDimmed || (hoveredAlert && !isHovered && !isSameSource)}
            isSameSourceHighlighted={isSameSource}
            onPointerOver={setHoveredAlert}
            onPointerOut={() => setHoveredAlert(null)}
            onClick={onNodeClick}
          />
        );
      })}
    </group>
  );
};

// WebGL Error Boundary Fallback
class WebGLErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>
          <AlertTriangle size={32} style={{ marginBottom: '8px', color: 'var(--severity-medium)' }} />
          <h4 style={{ margin: '0 0 6px 0', color: 'var(--text-primary)' }}>3D Canvas Hardware Acceleration Unavailable</h4>
          <p style={{ margin: 0, fontSize: '13px' }}>The 3D visualization could not be loaded on this display environment. Please refer to the audit log table below for full incident investigation.</p>
        </div>
      );
    }
    return this.props.children;
  }
}

// Main IncidentTimeline3D Component
export function IncidentTimeline3D({ history, onIncidentClick }) {
  const theme = useCurrentTheme();
  const [searchQuery, setSearchQuery] = useState('');
  const [resetTrigger, setResetTrigger] = useState(0);
  const [timeRange, setTimeRange] = useState('all'); // 'all', '1h', '6h', '24h'

  // Time-filtered dataset
  const filteredHistory = useMemo(() => {
    if (!history || history.length === 0) return [];
    if (timeRange === 'all') return history;

    // Find the latest recorded incident timestamp in history
    const latestSeen = Math.max(...history.map((h) => h.first_seen || 0));
    if (!latestSeen) return history;

    let seconds = 3600;
    if (timeRange === '6h') seconds = 21600;
    if (timeRange === '24h') seconds = 86400;

    return history.filter((h) => (h.first_seen || 0) >= latestSeen - seconds);
  }, [history, timeRange]);

  // Actual time window representation
  const timeWindow = useMemo(() => {
    if (!filteredHistory || filteredHistory.length === 0) return null;
    const timestamps = filteredHistory.map((h) => h.first_seen || 0).filter(t => t > 0);
    if (timestamps.length === 0) return null;

    const minT = Math.min(...timestamps);
    const maxT = Math.max(...timestamps);

    const minStr = formatShortTime(minT);
    const maxStr = formatShortTime(maxT);

    return { minStr, maxStr, count: filteredHistory.length };
  }, [filteredHistory]);

  // Check matching search query count
  const matchingSearchCount = useMemo(() => {
    if (!searchQuery.trim()) return null;
    const q = searchQuery.trim().toLowerCase();
    return filteredHistory.filter((alert) => {
      const src = (alert.source_ip || '').toLowerCase();
      const type = (alert.attack_type || '').toLowerCase();
      return src.includes(q) || type.includes(q);
    }).length;
  }, [filteredHistory, searchQuery]);

  // Empty state handling
  if (!history || history.length === 0) {
    return (
      <div className="incident-3d-container" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ textAlign: 'center', padding: '32px 20px', maxWidth: '420px' }}>
          <div style={{ display: 'inline-flex', padding: '16px', background: 'var(--surface-hover)', borderRadius: '50%', marginBottom: '16px' }}>
            <Shield size={32} color="var(--brand-violet)" />
          </div>
          <h3 style={{ margin: '0 0 8px 0', fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)' }}>
            NO DETECTED INCIDENTS
          </h3>
          <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-muted)', lineHeight: 1.5 }}>
            MONI has not recorded any threat incidents in the current history. The 3D threat timeline will automatically populate when network anomalies or intrusion attempts are flagged.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="incident-3d-container">
      {/* Top Left: Title, Real Time Window, Axes & Semantic Key */}
      <div className="incident-3d-overlay-top-left">
        <div className="incident-3d-title">
          <span>3D THREAT TIMELINE</span>
          <Clock size={13} color="var(--brand-violet)" />
        </div>

        {timeWindow && (
          <div className="incident-3d-window-badge" title="Actual chronological period represented by these detections">
            WINDOW: {timeWindow.minStr} — {timeWindow.maxStr}
          </div>
        )}

        <div className="incident-3d-axes-grid">
          <div className="incident-3d-axes-item">
            <strong>X AXIS</strong>
            <span>Chronology</span>
          </div>
          <div className="incident-3d-axes-item">
            <strong>Y AXIS</strong>
            <span>Severity / Conf</span>
          </div>
          <div className="incident-3d-axes-item">
            <strong>Z AXIS</strong>
            <span>Source Origin</span>
          </div>
        </div>

        <div className="incident-3d-legend-row">
          <div className="incident-3d-legend-group">
            <span className="incident-3d-legend-item">
              <span className="incident-3d-legend-dot" style={{ background: '#3b82f6' }} /> LOW
            </span>
            <span className="incident-3d-legend-item">
              <span className="incident-3d-legend-dot" style={{ background: '#f59e0b' }} /> MED
            </span>
            <span className="incident-3d-legend-item">
              <span className="incident-3d-legend-dot" style={{ background: '#ef4444' }} /> HIGH
            </span>
          </div>

          <div className="incident-3d-legend-group">
            <span className="incident-3d-legend-item">
              <span className="incident-3d-legend-dot" style={{ background: 'var(--severity-critical)', boxShadow: '0 0 4px var(--severity-critical)' }} /> ACTIVE
            </span>
            <span className="incident-3d-legend-item">
              <span className="incident-3d-legend-dot" style={{ background: 'var(--status-healthy)' }} /> RESOLVED
            </span>
          </div>
        </div>
      </div>

      {/* Top Right: Time Range Selector, Search IP/Threat, Reset View */}
      <div className="incident-3d-overlay-top-right">
        <div className="incident-3d-controls-card">
          {/* Time Range Filter */}
          <div className="incident-3d-range-selector" title="Filter chronological window">
            {[
              { id: 'all', label: 'All' },
              { id: '1h', label: '1h' },
              { id: '6h', label: '6h' },
              { id: '24h', label: '24h' },
            ].map((btn) => (
              <button
                key={btn.id}
                className={`incident-3d-range-btn ${timeRange === btn.id ? 'active' : ''}`}
                onClick={() => setTimeRange(btn.id)}
              >
                {btn.label}
              </button>
            ))}
          </div>

          {/* Search IP or Threat Type */}
          <div className="incident-3d-search-box">
            <Search size={13} color="var(--text-muted)" />
            <input
              type="text"
              placeholder="Search IP or Threat..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, display: 'flex' }}
                title="Clear search"
              >
                <X size={13} color="var(--text-muted)" />
              </button>
            )}
          </div>
        </div>

        {/* Reset Camera View Button */}
        <button
          className="incident-3d-reset-btn"
          onClick={() => setResetTrigger((prev) => prev + 1)}
          title="Auto-frame camera to fit all incidents"
        >
          <RotateCcw size={12} /> Reset View
        </button>

        {/* Search Query Feedback Banner */}
        {matchingSearchCount === 0 && (
          <div className="incident-3d-empty-banner">
            <AlertTriangle size={12} />
            <span>No matching incidents found</span>
            <button
              onClick={() => setSearchQuery('')}
              style={{ background: 'none', border: 'none', textDecoration: 'underline', color: 'inherit', cursor: 'pointer', fontSize: '11px', fontWeight: 700 }}
            >
              Clear
            </button>
          </div>
        )}
      </div>

      {/* Bottom Center: How to Read & Gesture Guide */}
      <div className="incident-3d-bottom-help">
        Each node = 1 incident · Lines = same-source correlation · Drag to orbit · Scroll to zoom · Right-drag to pan · Click node for drawer
      </div>

      {/* 3D Canvas */}
      <WebGLErrorBoundary>
        <Canvas 
          camera={{ position: [0, 12, 38], fov: 45 }}
          gl={{ antialias: true, alpha: true }}
        >
          <color attach="background" args={[theme === 'dark' ? '#121214' : '#FAF6F0']} />
          <ambientLight intensity={theme === 'dark' ? 0.7 : 0.9} />
          <directionalLight position={[15, 25, 15]} intensity={theme === 'dark' ? 1.6 : 1.8} castShadow />
          <directionalLight position={[-15, -15, -15]} intensity={0.4} />

          <TimelineNetwork
            alerts={filteredHistory}
            onNodeClick={onIncidentClick}
            searchQuery={searchQuery}
            resetTrigger={resetTrigger}
            theme={theme}
          />

          <OrbitControls
            enablePan={true}
            enableZoom={true}
            enableRotate={true}
            enableDamping={true}
            dampingFactor={0.1}
            minDistance={8}
            maxDistance={85}
            maxPolarAngle={Math.PI / 2 + 0.05}
            makeDefault
          />
        </Canvas>
      </WebGLErrorBoundary>
    </div>
  );
}
