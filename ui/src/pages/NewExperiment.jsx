import React from 'react';
import { Play } from 'lucide-react';
import { Panel, attacks, attackLabels } from '../shared';

const descriptions = {
    password_spray: 'One common password across many different accounts',
    mfa_fatigue: 'Bombarded MFA prompts and then approval',
    impossible_travel: 'Sign-ins from geographically distant locations',
    credential_compromise: 'Multiple failed logins followed by suspicious access',
};

export default function NewExperiment({ form, setForm, connected, running, launch }) {
    const invalidDevices = Number(form.devices) < Number(form.users);
    function toggle(key, value) {
        setForm(current => ({ ...current, [key]: current[key].includes(value)
            ? current[key].filter(item => item !== value) : [...current[key], value] }));
    }

    return <form className="experiment-builder" onSubmit={event => { event.preventDefault(); launch(form); }}>
        <div className="builder-grid">
            <Panel title="Baseline Traffic">
                <div className="inputs">
                    {[['events', 'Normal events', 1, 100000], ['seed', 'Random seed', 0, 2147483647],
                        ['users', 'Users', 1, 1000], ['devices', 'Devices', 1, 2000]].map(([key, label, min, max]) =>
                        <label key={key}>{label}<input type="number" min={min} max={max} step="1" required value={form[key]}
                            onChange={event => setForm({ ...form, [key]: event.target.value === '' ? '' : Number(event.target.value) })} /></label>)}
                </div>
                {invalidDevices && <p className="footnote validation-error" role="alert">Devices must be at least the number of users.</p>}
            </Panel>
            <Panel title="IAM Attack Scenarios">
                <div className="choices">{attacks.map(attack => <label className={'choice ' + (form.attacks.includes(attack) ? 'checked' : '')} key={attack}>
                    <input type="checkbox" checked={form.attacks.includes(attack)} onChange={() => toggle('attacks', attack)} />
                    <div><strong>{attackLabels[attack]}</strong><small>{descriptions[attack]}</small></div>
                </label>)}</div>
            </Panel>
            <section className="panel launch-panel">
                <h2>Experiment Parameters</h2>
                <dl>
                    <div><dt>Baseline events</dt><dd>{Number(form.events).toLocaleString()}</dd></div>
                    <div><dt>Random seed</dt><dd>{form.seed}</dd></div>
                    <div><dt>IAM Attack Scenarios</dt><dd>{form.attacks.length || 'Control run'}</dd></div>
                    <div><dt>Privacy Techniques</dt><dd>{form.arms.join(' / ').toUpperCase() || 'Select a technique'}</dd></div>
                    <div><dt>Users</dt><dd>{form.users}</dd></div>
                    <div><dt>Devices</dt><dd>{form.devices}</dd></div>
                </dl>
                <button className="primary" type="submit" disabled={!connected || running || !form.arms.length || invalidDevices}>
                    <Play size={16} />{running ? 'Experiment running…' : 'Generate & Run'}
                </button>
            </section>
        </div>
    </form>;
}
