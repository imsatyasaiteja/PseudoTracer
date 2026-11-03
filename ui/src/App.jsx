import React, { useEffect, useState } from 'react';
import { X } from 'lucide-react';
import logo from '../../assets/logo_bg.png';
import { api, arms, attacks, RunSummary } from './shared';
import CorrelationEngine from './pages/CorrelationEngine';
import PrivacyEngine from './pages/PrivacyEngine';
import NewExperiment from './pages/NewExperiment';
import Events from './pages/Events';
import Alerts from './pages/Alerts';
import Analyze from './pages/Analyze';
import Guide from './pages/Guide';

const pages = [
    'New Experiment', 'Events', 'Alerts', 'Correlation Engine', 'Privacy Engine', 'Analyze', 'Guide',
];

export default function App() {
    const [page, setPage] = useState('New Experiment');
    const [runs, setRuns] = useState([]);
    const [selected, setSelected] = useState('');
    const [connected, setConnected] = useState(false);
    const [checkedConnection, setCheckedConnection] = useState(false);
    const [error, setError] = useState('');
    const [busy, setBusy] = useState(false);
    const [pending, setPending] = useState('');
    const [refreshKey, setRefreshKey] = useState(0);
    const [form, setForm] = useState({ seed: 42, events: 3000, users: 20, devices: 30, attacks: [...attacks], arms: [...arms] });
    const [eventControls, setEventControls] = useState(null);
    const run = runs.find(item => item.id === selected);
    const running = busy || Boolean(pending) || runs.some(item => item.status === 'running');
    const showRunContext = !['New Experiment', 'Analyze', 'Guide'].includes(page);
    const showSummary = ['Events', 'Alerts', 'Correlation Engine', 'Privacy Engine'].includes(page);

    // Schedule after each response so slow requests never overlap.
    useEffect(() => {
        let active = true;
        let timer;
        const controller = new AbortController();
        async function refresh() {
            let delay = 8000;
            try {
                const data = await api('/runs', { signal: controller.signal });
                if (!active) return;
                setRuns(data);
                setConnected(true);
                setSelected(current => current || data[0]?.id || '');
                setPending(current => data.some(item => item.id === current) ? '' : current);
                if (data.some(item => item.status === 'running')) delay = 2000;
            } catch (error) {
                if (active) setConnected(false);
            } finally {
                if (active) {
                    setCheckedConnection(true);
                    timer = setTimeout(refresh, delay);
                }
            }
        }
        refresh();
        return () => { active = false; clearTimeout(timer); controller.abort(); };
    }, [refreshKey]);

    async function launch(settings) {
        setError('');
        setBusy(true);
        try {
            const result = await api('/runs', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(settings),
            });
            setPending(result.id);
            setSelected(result.id);
            setPage('Correlation Engine');
            setRefreshKey(value => value + 1);
        } catch (error) {
            setError(error.message);
        } finally {
            setBusy(false);
        }
    }

    return <div className={'app' + (showSummary || page === 'Analyze' ? ' viewport-app' : '') + (page === 'Analyze' ? ' analyze-workspace' : '') + (['Correlation Engine', 'Privacy Engine'].includes(page) ? ' engine-workspace' : '')}>
        <aside>
            <a className="brand" href="#new-experiment" onClick={event => { event.preventDefault(); setPage('New Experiment'); }}>
                <img className="brand-logo" src={logo} alt="PseudoTracer" />
            </a>
            <nav aria-label="Experiment workspace">
                {pages.map(name => <button key={name} className={page === name ? 'active' : ''}
                    aria-current={page === name ? 'page' : undefined} onClick={() => setPage(name)}>
                    {name}
                </button>)}
            </nav>
            <div className="sidebar-bottom"><small>IAM PRIVACY RESEARCH LAB</small></div>
        </aside>
        <div className="main">
            <header>
                <div className="header-title"><h1>{page}</h1></div>
                <span className={'connection ' + (connected ? 'online' : '')} role="status">
                    <i />{connected ? 'Engine Connected' : checkedConnection ? 'Engine Offline' : 'Connecting…'}
                </span>
            </header>
            <main className={showSummary || page === 'Analyze' ? "viewport-main" : undefined}>
                {showSummary && <RunSummary run={run} />}
                {checkedConnection && !connected && <div className="notice">
                    Engine Offline: Start <code>python ui/server.py</code> to load and run experiments
                    {runs.length > 0 && ' Displayed results are from the last connection.'}
                </div>}
                {error && <div className="notice error" role="alert">{error}
                    <button aria-label="Dismiss error" onClick={() => setError('')}><X size={16} /></button>
                </div>}
                {showRunContext && <div className="run-bar">
                    <label className="eyebrow" htmlFor="active-run">EXPERIMENT</label>
                    <select id="active-run" value={selected} onChange={event => setSelected(event.target.value)}>
                        <option value="" disabled>Select an experiment</option>
                        {pending && !runs.some(item => item.id === pending) && <option value={pending}>{pending} · starting</option>}
                        {runs.map(item => <option key={item.id} value={item.id}>{item.id}</option>)}
                    </select>
                    {['Events', 'Alerts'].includes(page) && <div className="event-controls" ref={setEventControls} />}
                </div>}
                <div className="tab-content">
                {page === 'New Experiment' && <NewExperiment form={form} setForm={setForm} connected={connected} running={running} launch={launch} />}
                {page === 'Events' && <Events key={selected} run={run} connected={connected} controls={eventControls} navigate={setPage} />}
                {page === 'Alerts' && <Alerts key={selected} run={run} connected={connected} controls={eventControls} navigate={setPage} />}
                {page === 'Correlation Engine' && <CorrelationEngine key={selected} run={run} pending={pending} navigate={setPage} />}
                {page === 'Privacy Engine' && <PrivacyEngine key={selected} run={run} pending={pending} navigate={setPage} />}
                {page === 'Analyze' && <Analyze runs={runs} selected={selected} />}
                {page === 'Guide' && <Guide navigate={setPage} run={run} connected={connected} />}
                </div>
            </main>
        </div>
    </div>;
}
