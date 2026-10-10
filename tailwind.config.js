// Palette steps read the CSS variables in tailwind.input.css, so colors are defined in one place.
const steps = [50, 100, 200, 300, 400, 500, 600, 700, 800, 900];
const rgb = name => `rgb(var(--${name}) / <alpha-value>)`;
// Optional role steps (e.g. --primary-text-600, --gray-fill-900) fall back to the base step.
const scale = (name, role) => Object.fromEntries(steps.map(step => [step, role
    ? `rgb(var(--${name}-${role}-${step}, var(--${name}-${step})) / <alpha-value>)`
    : rgb(`${name}-${step}`)]));

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
            // Dark mode: text needs lighter steps than fills, and 700-900 fills stay dark behind white text.
            textColor: {
                gray: scale('gray'),
                primary: scale('primary', 'text'),
                blue: scale('primary', 'text'),
                indigo: scale('primary', 'text'),
                red: scale('red', 'text'),
                green: scale('green', 'text'),
                emerald: scale('green', 'text'),
                amber: scale('amber', 'text'),
                yellow: scale('amber', 'text'),
                orange: scale('orange', 'text')
            },
            backgroundColor: { white: rgb('surface'), gray: scale('gray', 'fill') },
            gradientColorStops: { white: rgb('surface'), gray: scale('gray', 'fill') },
            borderColor: { white: rgb('surface-edge') },
            ringColor: { white: rgb('surface-edge') },
            ringOffsetColor: { DEFAULT: 'rgb(var(--gray-50))' },
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
