import React from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useWarRoom } from '../../context/WarRoomContext'
import SatelliteDroneMap from './SatelliteDroneMap'
import NeuralEngineWeb from './NeuralEngineWeb'
import SystemPulseEKG from './SystemPulseEKG'

export default function WarRoomLayout({ children }) {
  const { redTeamActive } = useWarRoom()

  return (
    <div className="flex flex-col h-full min-h-0 relative">
      <AnimatePresence>
        {redTeamActive && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="absolute inset-0 pointer-events-none z-20 rounded-xl"
            style={{
              background: 'radial-gradient(ellipse 80% 50% at 50% 0%, rgba(239,68,68,0.12) 0%, transparent 60%)',
              boxShadow: 'inset 0 0 120px rgba(239,68,68,0.08)',
            }}
          />
        )}
      </AnimatePresence>
      {redTeamActive && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="absolute top-2 left-1/2 -translate-x-1/2 z-30 px-4 py-1.5 rounded-lg border border-red-500/60 bg-red-950/80 backdrop-blur"
        >
          <motion.span
            animate={{ opacity: [1, 0.5, 1] }}
            transition={{ repeat: Infinity, duration: 1.2 }}
            className="text-xs font-bold text-red-400 tracking-widest"
          >
            SYSTEM EXPLOITATION ACTIVE — ROE OVERRIDDEN
          </motion.span>
        </motion.div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 p-4 flex-1 min-h-0">
        <motion.div
          className="lg:col-span-4 relative h-48 lg:h-64 rounded-2xl overflow-hidden border border-white/10"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.1 }}
        >
          <SatelliteDroneMap />
        </motion.div>
        <motion.div
          className="lg:col-span-8 relative h-48 lg:h-64 rounded-2xl overflow-hidden border border-white/10 flex items-center justify-center bg-slate-950/80"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.15 }}
        >
          <div className="w-full h-full p-2">
            <NeuralEngineWeb width={800} height={240} />
          </div>
        </motion.div>
      </div>

      <div className="shrink-0 px-4 pb-4">
        {children}
      </div>

      <motion.div
        className="shrink-0 px-4 pb-4"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.3 }}
      >
        <SystemPulseEKG />
      </motion.div>
    </div>
  )
}
