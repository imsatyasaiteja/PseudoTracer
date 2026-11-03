import React from 'react';
import { EventExplorer, EventTable, useEventExplorer } from '../shared';

export default function Events({ run, connected, controls, navigate }) {
    const explorer = useEventExplorer({ run, connected });
    const { arm, data, query, refreshKey, start } = explorer;
    return <EventExplorer explorer={explorer} controls={controls} navigate={navigate}>
        <EventTable key={`${arm}-${data.page}-${query}-${refreshKey}`} events={data.events} start={start} />
    </EventExplorer>;
}
