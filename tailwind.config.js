// Palette steps read the CSS variables in tailwind.input.css, so colors are defined in one place.
const steps = [50, 100, 200, 300, 400, 500, 600, 700, 800, 900];
const scale = name => Object.fromEntries(steps.map(step => [step, `rgb(var(--${name}-${step}) / <alpha-value>)`]));

module.exports = {
    content: ['./public/index.html', './public/admin.html'],
    theme: {
        extend: {
            fontFamily: {
                sans: 'var(--font-sans)',
                mono: 'var(--font-mono)'
            },
            // 800/900 render as faux-bold blobs in YaHei and PingFang; 700 is the heaviest real weight.
            fontWeight: {
                extrabold: '700',
                black: '700'
            },
            colors: {
                gray: scale('gray'),
                primary: scale('primary'),
                blue: scale('primary'),
                indigo: scale('primary'),
                red: scale('red'),
                green: scale('green'),
                emerald: scale('green'),
                amber: scale('amber'),
                yellow: scale('amber'),
                orange: scale('orange')
            },
            borderRadius: {
                '2xl': '1rem',
                '3xl': '1.25rem'
            },
            animation: {
                'fade-in': 'fadeIn var(--dur-2) ease-out',
                'slide-up': 'slideUp var(--dur-3) var(--ease-out)',
                'slide-down': 'slideDown var(--dur-3) var(--ease-out)',
                'scale-in': 'scaleIn var(--dur-2) var(--ease-out)',
                'detail-scale-in': 'detailScaleIn 0.42s var(--ease-out)',
                'slide-up-mobile': 'slideUpMobile 0.5s var(--ease-out)',
                'detail-slide-up-mobile': 'detailSlideUpMobile 0.56s var(--ease-out)',
                'zoom-in': 'zoomIn var(--dur-3) var(--ease-out)'
            },
            keyframes: {
                fadeIn: { '0%': { opacity: '0' }, '100%': { opacity: '1' } },
                slideUp: { '0%': { transform: 'translateY(12px)', opacity: '0' }, '100%': { transform: 'translateY(0)', opacity: '1' } },
                slideDown: { '0%': { transform: 'translateY(-12px)', opacity: '0' }, '100%': { transform: 'translateY(0)', opacity: '1' } },
                scaleIn: { '0%': { transform: 'translateY(6px) scale(0.97)', opacity: '0' }, '100%': { transform: 'translateY(0) scale(1)', opacity: '1' } },
                detailScaleIn: { '0%': { transform: 'translateY(14px) scale(0.97)', opacity: '0' }, '100%': { transform: 'translateY(0) scale(1)', opacity: '1' } },
                slideUpMobile: { '0%': { transform: 'translateY(100%)' }, '100%': { transform: 'translateY(0)' } },
                detailSlideUpMobile: { '0%': { transform: 'translateY(100%)' }, '100%': { transform: 'translateY(0)' } },
                zoomIn: { '0%': { transform: 'scale(0.94)', opacity: '0' }, '100%': { transform: 'scale(1)', opacity: '1' } }
            },
            boxShadow: {
                soft: 'var(--shadow-1)',
                card: 'var(--shadow-1)'
            }
        }
    }
};
