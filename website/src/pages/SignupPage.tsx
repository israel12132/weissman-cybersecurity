import { Layout } from '../components/Layout'
import { SignupForm } from '../components/SignupForm'
import { cta } from '../content/site'

export function SignupPage() {
  return (
    <Layout announce={false}>
      <div className="site-wrap flex min-h-[70vh] items-center justify-center py-16">
        <div className="surface w-full max-w-md p-8">
          <h1 className="display text-2xl text-ink">Create your workspace</h1>
          <p className="mt-2 text-sm text-muted">14-day free trial · no credit card. Signup is disabled unless the operator turns it on.</p>
          <div className="mt-8">
            <SignupForm />
          </div>
          <p className="mt-8 text-center text-xs text-dim">
            Already have an account?{' '}
            <a className="text-accent" href={cta.signIn.href}>
              Sign in
            </a>
          </p>
        </div>
      </div>
    </Layout>
  )
}
