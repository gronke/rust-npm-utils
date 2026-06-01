import { LitElement, html, css } from 'lit';
import { Temporal } from 'temporal-polyfill';

// The full IANA time-zone list, straight from the runtime, with a small
// fallback for older engines that lack `Intl.supportedValuesOf`.
const ZONES =
  typeof Intl.supportedValuesOf === 'function'
    ? Intl.supportedValuesOf('timeZone')
    : ['UTC', 'Europe/Berlin', 'America/New_York', 'Asia/Tokyo'];

/// Converts a wall-clock date-time from one IANA time zone to another using
/// `Temporal.PlainDateTime` → `ZonedDateTime` → `withTimeZone`.
class DateConverter extends LitElement {
  static properties = {
    local: { type: String },
    from: { type: String },
    to: { type: String },
  };

  static styles = css`
    :host {
      display: block;
      border: 1px solid #ddd;
      border-radius: 8px;
      padding: 1rem 1.25rem;
    }
    label {
      display: block;
      margin: 0.5rem 0 0.15rem;
      font-weight: 600;
    }
    input,
    select {
      font: inherit;
      padding: 0.3rem;
      min-width: 16rem;
    }
    output {
      display: block;
      margin-top: 1rem;
      padding: 0.75rem;
      background: #f4f6f8;
      border-radius: 6px;
      font-variant-numeric: tabular-nums;
    }
  `;

  constructor() {
    super();
    this.local = '2026-01-01T12:00';
    this.from = 'Europe/Berlin';
    this.to = 'America/New_York';
  }

  get converted() {
    try {
      const source = Temporal.PlainDateTime.from(this.local).toZonedDateTime(this.from);
      const target = source.withTimeZone(this.to);
      const fmt = (z) =>
        z.toLocaleString('en-US', {
          year: 'numeric',
          month: 'short',
          day: 'numeric',
          hour: 'numeric',
          minute: '2-digit',
          timeZoneName: 'short',
        });
      return `${fmt(source)}\n→ ${fmt(target)}`;
    } catch (err) {
      return `Invalid input: ${err.message}`;
    }
  }

  zoneSelect(value, onChange) {
    return html`<select @change=${onChange}>
      ${ZONES.map((z) => html`<option ?selected=${z === value} value=${z}>${z}</option>`)}
    </select>`;
  }

  render() {
    return html`
      <label>Wall-clock date &amp; time</label>
      <input
        type="datetime-local"
        .value=${this.local}
        @input=${(e) => (this.local = e.target.value)}
      />

      <label>From zone</label>
      ${this.zoneSelect(this.from, (e) => (this.from = e.target.value))}

      <label>To zone</label>
      ${this.zoneSelect(this.to, (e) => (this.to = e.target.value))}

      <output>${this.converted}</output>
    `;
  }
}

customElements.define('date-converter', DateConverter);
