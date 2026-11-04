import type { InputHTMLAttributes, ReactNode } from "react";

interface FieldProps {
  label: string;
  htmlFor?: string;
  optional?: boolean;
  hint?: string;
  error?: string;
  children: ReactNode;
}

export function Field({ label, htmlFor, optional = false, hint, error, children }: FieldProps) {
  return (
    <div className="field">
      <label className="field-label" htmlFor={htmlFor}>
        {label}
        {optional ? <span className="optional"> optional</span> : null}
      </label>
      {children}
      {hint ? <span className="field-hint">{hint}</span> : null}
      {error ? (
        <p className="field-error" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}

export function TextInput(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input className="field-input" {...props} />;
}
