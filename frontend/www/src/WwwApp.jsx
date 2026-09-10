import { useEffect } from 'react'
import { Route, Routes } from 'react-router'
import WwwShell from './components/WwwShell'
import Platform from './pages/Platform'
import Engines from './pages/Engines'
import HowItWorks from './pages/HowItWorks'
import Pricing from './pages/Pricing'
import Security from './pages/Security'
import Contact from './pages/Contact'
import Signup from './pages/Signup'
import Company from './pages/Company'
import Login from './pages/Login'
import NotFound from './pages/NotFound'

/** `/` is the original static marketing homepage — never the React shell. */
function HardPublicHome() {
  useEffect(() => {
    window.location.replace('/')
  }, [])
  return null
}

export default function WwwApp() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/" element={<HardPublicHome />} />
      <Route path="/he" element={<HardPublicHome />} />
      <Route element={<WwwShell />}>
        <Route path="platform" element={<Platform />} />
        <Route path="platform/:layer" element={<Platform />} />
        <Route path="engines" element={<Engines />} />
        <Route path="how-it-works" element={<HowItWorks />} />
        <Route path="pricing" element={<Pricing />} />
        <Route path="security" element={<Security />} />
        <Route path="contact" element={<Contact />} />
        <Route path="signup" element={<Signup />} />
        <Route path="company" element={<Company />} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  )
}
