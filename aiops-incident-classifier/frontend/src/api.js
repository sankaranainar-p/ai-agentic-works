import axios from 'axios'

const api = axios.create({ baseURL: '/api' })

export const getHealth   = ()            => api.get('/health')
export const getStats    = ()            => api.get('/stats')
export const getIncidents = (limit = 50) => api.get(`/incidents?limit=${limit}`)
export const classify    = (payload)     => api.post('/classify', payload)
