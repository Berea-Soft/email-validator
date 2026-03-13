import { defineConfig } from 'vite';
import { resolve } from 'path';
import dts from 'vite-plugin-dts';
import pack from "./package.json";


const banner = `/*! email-validator v${
  pack.version
} | (c) ${new Date().getFullYear()} Berea-Soft | MIT License | https://github.com/Berea-Soft/email-validator */`;

export default defineConfig({
  build: {
    lib: {
      // Punto de entrada principal
      entry: resolve(__dirname, 'src/index.ts'),
      // Nombre global para UMD/IIFE: debe ser un identificador JS valido
      name: 'BereasoftEmailValidator',
      // Nombres de archivo personalizados
      fileName: (format) => `email-validator.${format === "cjs" ? "cjs" : `${format}.js`}`,
      formats: ["es", "cjs", "umd", "iife"],
    },
    rollupOptions: {
      // Aseguramos que los módulos externos no se incluyan en el bundle
      external: ['dns', 'dns/promises', 'fetch'],
      output: {
        // Configuramos para que no se inyecten globales en el bundle
        globals: {
          dns: 'dns',
          'dns/promises': 'dnsPromises',
        },
        // Agregar banner a cada formato
        banner,
      },
    },
    // Limpiar la carpeta de salida antes de cada build
    emptyOutDir: true,
    // Generar source maps para facilitar el debugging
    sourcemap: false,
    // Minimizar el código para producción
    minify: 'esbuild',
  },
  plugins: [
    // Generar archivos de definición de tipos (.d.ts) automáticamente
    dts({
      rollupTypes: true,
      insertTypesEntry: true,
      include: ['src/**/*.ts'],
      outDir: 'dist/types',
    }),
  ],
});
