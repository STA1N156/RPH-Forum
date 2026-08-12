module.exports = {
    content: ['./public/index.html', './public/admin.html'],
    theme: {
        extend: {
            fontFamily: {
                sans: ['PingFang SC', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'Helvetica Neue', 'Arial', 'Noto Sans', 'sans-serif', 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol', 'Noto Color Emoji']
            },
            colors: {
                primary: {
                    50: '#eff6ff',
                    100: '#dbeafe',
                    200: '#bfdbfe',
                    300: '#93c5fd',
                    400: '#60a5fa',
                    500: '#3b82f6',
                    600: '#2563eb',
                    700: '#1d4ed8',
                    800: '#1e40af',
                    900: '#1e3a8a'
                }
            },
            animation: {
                'fade-in': 'fadeIn 0.3s ease-out',
                'slide-up': 'slideUp 0.3s ease-out',
                'slide-down': 'slideDown 0.3s ease-out',
                'scale-in': 'scaleIn 0.2s ease-out',
                'detail-scale-in': 'detailScaleIn 0.48s cubic-bezier(0.22, 1, 0.36, 1)',
                'slide-up-mobile': 'slideUpMobile 0.5s cubic-bezier(0.32, 0.72, 0, 1)',
                'detail-slide-up-mobile': 'detailSlideUpMobile 0.72s cubic-bezier(0.22, 1, 0.36, 1)',
                'zoom-in': 'zoomIn 0.3s ease-out'
            },
            keyframes: {
                fadeIn: { '0%': { opacity: '0' }, '100%': { opacity: '1' } },
                slideUp: { '0%': { transform: 'translateY(20px)', opacity: '0' }, '100%': { transform: 'translateY(0)', opacity: '1' } },
                slideDown: { '0%': { transform: 'translateY(-20px)', opacity: '0' }, '100%': { transform: 'translateY(0)', opacity: '1' } },
                scaleIn: { '0%': { transform: 'scale(0.95)', opacity: '0' }, '100%': { transform: 'scale(1)', opacity: '1' } },
                detailScaleIn: { '0%': { transform: 'scale(0.94) translateY(18px)', opacity: '0' }, '100%': { transform: 'scale(1) translateY(0)', opacity: '1' } },
                slideUpMobile: { '0%': { transform: 'translateY(100%)' }, '100%': { transform: 'translateY(0)' } },
                detailSlideUpMobile: { '0%': { transform: 'translateY(100%)' }, '100%': { transform: 'translateY(0)' } },
                zoomIn: { '0%': { transform: 'scale(0.9)', opacity: '0' }, '100%': { transform: 'scale(1)', opacity: '1' } }
            },
            boxShadow: {
                soft: '0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03)',
                card: '0 0 0 1px rgba(0,0,0,0.03), 0 2px 8px rgba(0,0,0,0.04)'
            }
        }
    }
};
