package org.openolly.reporting;

/** Passes only monitored and blocked events to another sink. */
public class ViolationsOnlySink implements EventSink {

	private final EventSink delegate;

	public ViolationsOnlySink(EventSink delegate) {
		this.delegate = delegate;
	}

	@Override
	public void accept(Event event) {
		if ( event.getAction() != Event.Action.OBSERVED ) delegate.accept( event );
	}

	@Override
	public void close() {
		delegate.close();
	}

	@Override
	public String toString() {
		return delegate.toString();
	}

}
