import { useState } from 'react'

const featureItems = [
  'Dashboard',
  'Static PE Analysis',
  'YARA Signature Engine',
  'Intelligence History',
]

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false)
  const [page, setPage] = useState('login')
  const [activeFeature, setActiveFeature] = useState('Dashboard')

  const handleAuthSubmit = (mode) => {
    setPage(mode)
    setIsLoggedIn(true)
    setActiveFeature('Dashboard')
  }

  const handleLogout = () => {
    setIsLoggedIn(false)
    setPage('login')
    setActiveFeature('Dashboard')
  }

  const isDashboardView = isLoggedIn && page === 'dashboard'

  return (
    <div className="min-h-screen bg-cyber-navy text-slate-100">
      {isDashboardView ? (
        <div className="flex min-h-screen bg-cyber-navy">
          <aside className="flex w-80 flex-col border-r border-slate-800 bg-cyber-slate p-8 shadow-[0_0_30px_rgba(37,165,255,0.12)]">
            <div className="mb-10">
              <p className="text-sm uppercase tracking-[0.35em] text-cyber-blue/70">
                Threat Intelligence
              </p>
              <h1 className="mt-3 text-3xl font-black tracking-[0.2em] text-white">
                BLUEINTEL
              </h1>
            </div>

            <nav className="space-y-3">
              {featureItems.map((item) => {
                const isActive = activeFeature === item
                return (
                  <button
                    key={item}
                    type="button"
                    onClick={() => setActiveFeature(item)}
                    className={`flex w-full items-center rounded-xl px-4 py-3 text-left text-sm font-medium transition ${
                      isActive
                        ? 'bg-slate-800/80 text-cyber-blue shadow-[0_0_18px_rgba(37,165,255,0.15)]'
                        : 'text-slate-300 hover:bg-slate-800/60 hover:text-white'
                    }`}
                  >
                    {item}
                  </button>
                )
              })}
            </nav>

            <div className="mt-auto rounded-2xl border border-slate-700/80 bg-slate-900/70 p-4 text-sm text-slate-400">
              <p className="font-semibold text-slate-200">Session ready</p>
              <p className="mt-1">Static scanning and YARA operations are primed for inspection.</p>
            </div>
          </aside>

          <main className="flex-1 p-8">
            <div className="flex items-center justify-between rounded-2xl border border-slate-800/80 bg-slate-900/50 px-6 py-4">
              <div>
                <p className="text-sm uppercase tracking-[0.3em] text-cyber-blue/70">
                  Workspace
                </p>
                <h2 className="text-2xl font-semibold text-white">{activeFeature}</h2>
              </div>
              <button
                type="button"
                onClick={handleLogout}
                className="rounded-full border border-cyber-blue/40 px-4 py-2 text-sm font-medium text-cyber-blue transition hover:bg-cyber-blue/10"
              >
                Logout
              </button>
            </div>

            <div className="mt-8 rounded-3xl border border-slate-800 bg-cyber-slate/80 p-8 shadow-[0_0_35px_rgba(37,165,255,0.12)]">
              <div className="mb-6">
                <p className="text-sm uppercase tracking-[0.3em] text-cyber-blue/70">
                  Intake queue
                </p>
                <h3 className="mt-2 text-2xl font-semibold text-white">
                  Drop in a new PE sample or YARA package
                </h3>
              </div>

              <label className="flex cursor-pointer flex-col items-center justify-center rounded-3xl border border-dashed border-cyber-blue bg-slate-950/60 px-8 py-16 text-center transition hover:border-cyber-blue/80 hover:bg-slate-900/90">
                <span className="text-4xl font-black text-cyber-blue">+</span>
                <span className="mt-3 text-lg font-semibold text-white">
                  Upload artifact
                </span>
                <span className="mt-2 text-sm text-slate-400">
                  Drag and drop or click to browse for suspicious binaries.
                </span>
                <input type="file" className="hidden" />
              </label>
            </div>
          </main>
        </div>
      ) : (
        <div className="flex min-h-screen items-center justify-center bg-[radial-gradient(circle_at_top,_rgba(37,165,255,0.16),_transparent_45%),linear-gradient(135deg,_#020212,_#0e172a)] px-4 py-10">
          <div className="w-full max-w-md rounded-[2rem] border border-slate-800/80 bg-cyber-slate p-8 shadow-[0_0_45px_rgba(37,165,255,0.16)]">
            <div className="mb-8 text-center">
              <p className="text-sm uppercase tracking-[0.35em] text-cyber-blue/70">
                BlueIntel
              </p>
              <h1 className="mt-3 text-5xl font-black uppercase tracking-[0.24em] text-white">
                BlueIntel
              </h1>
              <p className="mt-3 text-sm text-slate-400">
                Secure malware analysis and intelligence workflows in one place.
              </p>
            </div>

            <div className="mb-6 flex rounded-full border border-slate-700 bg-slate-950/80 p-1">
              <button
                type="button"
                onClick={() => setPage('login')}
                className={`flex-1 rounded-full px-3 py-2 text-sm font-semibold transition ${
                  page === 'login' ? 'bg-cyber-blue text-slate-950' : 'text-slate-300'
                }`}
              >
                Login
              </button>
              <button
                type="button"
                onClick={() => setPage('signup')}
                className={`flex-1 rounded-full px-3 py-2 text-sm font-semibold transition ${
                  page === 'signup' ? 'bg-cyber-blue text-slate-950' : 'text-slate-300'
                }`}
              >
                Signup
              </button>
            </div>

            <form className="space-y-4" onSubmit={(event) => event.preventDefault()}>
              <div>
                <label className="mb-2 block text-sm text-slate-400" htmlFor="email">
                  Email
                </label>
                <input
                  id="email"
                  type="email"
                  placeholder="analyst@blueintel.io"
                  className="w-full rounded-2xl border border-slate-700 bg-slate-950/80 px-4 py-3 text-sm text-white outline-none transition focus:border-cyber-blue focus:shadow-[0_0_0_2px_rgba(37,165,255,0.25)]"
                />
              </div>

              <div>
                <label className="mb-2 block text-sm text-slate-400" htmlFor="password">
                  Password
                </label>
                <input
                  id="password"
                  type="password"
                  placeholder="••••••••"
                  className="w-full rounded-2xl border border-slate-700 bg-slate-950/80 px-4 py-3 text-sm text-white outline-none transition focus:border-cyber-blue focus:shadow-[0_0_0_2px_rgba(37,165,255,0.25)]"
                />
              </div>

              {page === 'signup' && (
                <div>
                  <label className="mb-2 block text-sm text-slate-400" htmlFor="confirm">
                    Confirm password
                  </label>
                  <input
                    id="confirm"
                    type="password"
                    placeholder="••••••••"
                    className="w-full rounded-2xl border border-slate-700 bg-slate-950/80 px-4 py-3 text-sm text-white outline-none transition focus:border-cyber-blue focus:shadow-[0_0_0_2px_rgba(37,165,255,0.25)]"
                  />
                </div>
              )}

              <button
                type="button"
                onClick={() => handleAuthSubmit('dashboard')}
                className="w-full rounded-2xl bg-cyber-blue px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyber-blue/90"
              >
                {page === 'signup' ? 'Create account' : 'Sign in'}
              </button>
            </form>

            <p className="mt-6 text-center text-sm text-slate-500">
              {page === 'signup'
                ? 'Already have an account? '
                : 'Need an account? '}
              <button
                type="button"
                onClick={() => setPage(page === 'signup' ? 'login' : 'signup')}
                className="font-medium text-cyber-blue transition hover:text-cyber-blue/80"
              >
                {page === 'signup' ? 'Sign in instead' : 'Create one'}
              </button>
            </p>
          </div>
        </div>
      )}
    </div>
  )
}

export default App
