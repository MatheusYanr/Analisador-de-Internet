"""
Script de instalação do Monitor de Rede Professional
"""

import os

# Conteúdo completo do monitor
MONITOR_CODE = r'''
"""
Sistema Completo de Monitoramento de Rede - Windows
Versão: 2.0 Professional
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
import time
import socket
import psutil
import json
import csv
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import subprocess
import urllib.request
import statistics
from collections import deque
import os
import winsound


class NetworkMonitor:
    def __init__(self):
        self.monitoring = False
        self.data_queue = queue.Queue()
        self.ping_history = deque(maxlen=500)
        self.timestamps = deque(maxlen=500)
        self.packet_loss_history = deque(maxlen=100)
        self.download_speed_history = deque(maxlen=50)
        
        # Servidores para monitoramento
        self.servers = {
            'Google DNS': '8.8.8.8',
            'Cloudflare': '1.1.1.1',
            'OpenDNS': '208.67.222.222',
            'Google': 'www.google.com',
            'GitHub': 'github.com'
        }
        
        self.current_server = '8.8.8.8'
        self.interval = 1.0
        self.alert_threshold = 100
        self.packet_loss_threshold = 5
        
        self.stats = {
            'total_pings': 0,
            'successful_pings': 0,
            'failed_pings': 0,
            'min_latency': float('inf'),
            'max_latency': 0,
            'avg_latency': 0,
            'packet_loss': 0,
            'alerts_triggered': 0,
            'start_time': None
        }
        
        self.config_file = 'network_monitor_config.json'
        self.log_file = 'network_monitor_log.csv'
        self.enable_alerts = True
        self.enable_sound_alerts = True
        self.enable_auto_export = True
        
        self.load_config()
    
    def load_config(self):
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.interval = config.get('interval', 1.0)
                    self.alert_threshold = config.get('alert_threshold', 100)
                    self.packet_loss_threshold = config.get('packet_loss_threshold', 5)
                    self.enable_alerts = config.get('enable_alerts', True)
                    self.enable_sound_alerts = config.get('enable_sound_alerts', True)
        except Exception as e:
            print(f"Erro ao carregar configurações: {e}")
    
    def save_config(self):
        try:
            config = {
                'interval': self.interval,
                'alert_threshold': self.alert_threshold,
                'packet_loss_threshold': self.packet_loss_threshold,
                'enable_alerts': self.enable_alerts,
                'enable_sound_alerts': self.enable_sound_alerts
            }
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            print(f"Erro ao salvar configurações: {e}")
    
    def ping_host(self, host):
        try:
            result = subprocess.run(
                ['ping', '-n', '1', '-w', '2000', host],
                capture_output=True,
                text=True,
                timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            output = result.stdout.lower()
            
            if 'tempo=' in output:
                for line in output.split('\\n'):
                    if 'tempo=' in line and 'ms' in line:
                        time_str = line.split('tempo=')[1].split('ms')[0].strip()
                        return float(time_str)
            elif 'time=' in output:
                for line in output.split('\\n'):
                    if 'time=' in line and 'ms' in line:
                        time_str = line.split('time=')[1].split('ms')[0].strip()
                        return float(time_str)
            
            return None
        except Exception as e:
            return None
    
    def monitor_loop(self, callback):
        self.stats['start_time'] = datetime.now()
        consecutive_failures = 0
        
        while self.monitoring:
            try:
                start_time = time.time()
                
                latency = self.ping_host(self.current_server)
                timestamp = datetime.now()
                
                self.stats['total_pings'] += 1
                
                if latency is not None:
                    self.stats['successful_pings'] += 1
                    consecutive_failures = 0
                    
                    self.ping_history.append(latency)
                    self.timestamps.append(timestamp)
                    
                    if latency < self.stats['min_latency']:
                        self.stats['min_latency'] = latency
                    if latency > self.stats['max_latency']:
                        self.stats['max_latency'] = latency
                    
                    if len(self.ping_history) > 0:
                        self.stats['avg_latency'] = statistics.mean(self.ping_history)
                    
                    alert = None
                    if self.enable_alerts and latency > self.alert_threshold:
                        alert = f"ALERTA: Latência alta detectada! {latency:.1f}ms"
                        self.stats['alerts_triggered'] += 1
                        if self.enable_sound_alerts:
                            try:
                                winsound.Beep(1000, 200)
                            except:
                                pass
                    
                    data = {
                        'type': 'ping',
                        'latency': latency,
                        'timestamp': timestamp,
                        'status': 'success',
                        'alert': alert
                    }
                    callback(data)
                    
                else:
                    self.stats['failed_pings'] += 1
                    consecutive_failures += 1
                    
                    alert = None
                    if consecutive_failures >= 3:
                        alert = f"ALERTA: Conexão perdida! {consecutive_failures} falhas consecutivas"
                        self.stats['alerts_triggered'] += 1
                        if self.enable_sound_alerts:
                            try:
                                winsound.Beep(500, 500)
                            except:
                                pass
                    
                    data = {
                        'type': 'ping',
                        'latency': None,
                        'timestamp': timestamp,
                        'status': 'failed',
                        'alert': alert
                    }
                    callback(data)
                
                if self.stats['total_pings'] > 0:
                    self.stats['packet_loss'] = (self.stats['failed_pings'] / self.stats['total_pings']) * 100
                
                self.log_to_file(timestamp, latency)
                
                elapsed = time.time() - start_time
                sleep_time = max(0, self.interval - elapsed)
                time.sleep(sleep_time)
                
            except Exception as e:
                print(f"Erro no loop de monitoramento: {e}")
                time.sleep(self.interval)
    
    def log_to_file(self, timestamp, latency):
        try:
            file_exists = os.path.exists(self.log_file)
            with open(self.log_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(['Timestamp', 'Server', 'Latency (ms)', 'Status'])
                
                status = 'Success' if latency is not None else 'Failed'
                latency_str = f'{latency:.2f}' if latency is not None else 'N/A'
                writer.writerow([timestamp.strftime('%Y-%m-%d %H:%M:%S'), self.current_server, latency_str, status])
        except Exception as e:
            print(f"Erro ao salvar log: {e}")
    
    def start_monitoring(self, callback):
        if not self.monitoring:
            self.monitoring = True
            thread = threading.Thread(target=self.monitor_loop, args=(callback,), daemon=True)
            thread.start()
    
    def stop_monitoring(self):
        self.monitoring = False
    
    def reset_stats(self):
        self.stats = {
            'total_pings': 0,
            'successful_pings': 0,
            'failed_pings': 0,
            'min_latency': float('inf'),
            'max_latency': 0,
            'avg_latency': 0,
            'packet_loss': 0,
            'alerts_triggered': 0,
            'start_time': None
        }
        self.ping_history.clear()
        self.timestamps.clear()
    
    def get_network_interfaces(self):
        try:
            interfaces = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            
            info = []
            for interface_name, addresses in interfaces.items():
                if interface_name in stats:
                    stat = stats[interface_name]
                    if stat.isup:
                        for addr in addresses:
                            if addr.family == socket.AF_INET:
                                info.append({
                                    'name': interface_name,
                                    'ip': addr.address,
                                    'speed': stat.speed
                                })
            return info
        except Exception as e:
            return []


class MonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Monitor de Rede Professional - v2.0")
        self.root.geometry("1400x900")
        self.root.configure(bg='#1e1e1e')
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()
        
        self.monitor = NetworkMonitor()
        self.update_interval = 100
        
        self.create_widgets()
        self.update_gui()
    
    def configure_styles(self):
        bg_dark = '#1e1e1e'
        bg_medium = '#2d2d2d'
        fg_light = '#ffffff'
        accent = '#007acc'
        success = '#4ec9b0'
        error = '#f48771'
        
        self.style.configure('TFrame', background=bg_dark)
        self.style.configure('TLabel', background=bg_dark, foreground=fg_light, font=('Segoe UI', 10))
        self.style.configure('Title.TLabel', font=('Segoe UI', 16, 'bold'), foreground=accent)
        self.style.configure('TButton', font=('Segoe UI', 10))
        self.style.configure('Success.TButton', foreground=success)
        self.style.configure('Danger.TButton', foreground=error)
        self.style.configure('TCombobox', fieldbackground=bg_medium, background=bg_medium)
        self.style.configure('TNotebook', background=bg_dark, borderwidth=0)
        self.style.configure('TNotebook.Tab', padding=[20, 10], font=('Segoe UI', 10))
    
    def create_widgets(self):
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill='x', padx=10, pady=10)
        
        title = ttk.Label(header_frame, text="🌐 Monitor de Rede Professional", style='Title.TLabel')
        title.pack(side='left')
        
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.tab_monitor = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_monitor, text='📊 Monitoramento')
        self.create_monitor_tab()
        
        self.tab_stats = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_stats, text='📈 Estatísticas')
        self.create_stats_tab()
        
        self.tab_logs = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_logs, text='📋 Logs')
        self.create_logs_tab()
        
        self.tab_config = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_config, text='⚙️ Configurações')
        self.create_config_tab()
    
    def create_monitor_tab(self):
        control_frame = ttk.LabelFrame(self.tab_monitor, text='Controles', padding=10)
        control_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(control_frame, text='Servidor:').grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.server_combo = ttk.Combobox(control_frame, values=list(self.monitor.servers.keys()), width=20)
        self.server_combo.set('Google DNS')
        self.server_combo.grid(row=0, column=1, padx=5, pady=5)
        self.server_combo.bind('<<ComboboxSelected>>', self.on_server_change)
        
        ttk.Label(control_frame, text='Intervalo (s):').grid(row=0, column=2, padx=5, pady=5, sticky='w')
        self.interval_spin = ttk.Spinbox(control_frame, from_=0.5, to=60, increment=0.5, width=10)
        self.interval_spin.set(self.monitor.interval)
        self.interval_spin.grid(row=0, column=3, padx=5, pady=5)
        
        self.start_btn = ttk.Button(control_frame, text='▶ Iniciar', command=self.start_monitoring, style='Success.TButton')
        self.start_btn.grid(row=0, column=4, padx=5, pady=5)
        
        self.stop_btn = ttk.Button(control_frame, text='⏸ Parar', command=self.stop_monitoring, state='disabled', style='Danger.TButton')
        self.stop_btn.grid(row=0, column=5, padx=5, pady=5)
        
        ttk.Button(control_frame, text='🔄 Resetar', command=self.reset_data).grid(row=0, column=6, padx=5, pady=5)
        
        status_frame = ttk.LabelFrame(self.tab_monitor, text='Status Atual', padding=10)
        status_frame.pack(fill='x', padx=10, pady=5)
        
        self.status_labels = {}
        status_items = [
            ('Estado:', 'status'),
            ('Latência Atual:', 'current_latency'),
            ('Mínima:', 'min_latency'),
            ('Máxima:', 'max_latency'),
            ('Média:', 'avg_latency'),
            ('Perda de Pacotes:', 'packet_loss')
        ]
        
        for i, (label, key) in enumerate(status_items):
            ttk.Label(status_frame, text=label).grid(row=i//3, column=(i%3)*2, padx=10, pady=5, sticky='w')
            self.status_labels[key] = ttk.Label(status_frame, text='--', font=('Segoe UI', 10, 'bold'))
            self.status_labels[key].grid(row=i//3, column=(i%3)*2+1, padx=10, pady=5, sticky='w')
        
        graph_frame = ttk.LabelFrame(self.tab_monitor, text='Gráfico de Latência em Tempo Real', padding=10)
        graph_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.fig = Figure(figsize=(10, 4), facecolor='#2d2d2d')
        self.ax = self.fig.add_subplot(111, facecolor='#1e1e1e')
        self.ax.set_xlabel('Tempo', color='white')
        self.ax.set_ylabel('Latência (ms)', color='white')
        self.ax.tick_params(colors='white')
        self.ax.grid(True, alpha=0.3)
        
        self.canvas = FigureCanvasTkAgg(self.fig, graph_frame)
        self.canvas.get_tk_widget().pack(fill='both', expand=True)
    
    def create_stats_tab(self):
        summary_frame = ttk.LabelFrame(self.tab_stats, text='Resumo da Sessão', padding=20)
        summary_frame.pack(fill='x', padx=10, pady=10)
        
        self.stats_labels = {}
        stats_items = [
            ('Tempo de Monitoramento:', 'uptime'),
            ('Total de Pings:', 'total_pings'),
            ('Pings Bem-sucedidos:', 'successful_pings'),
            ('Pings Falhados:', 'failed_pings'),
            ('Taxa de Sucesso:', 'success_rate'),
            ('Alertas Disparados:', 'alerts_triggered'),
            ('Latência Mínima:', 'min_latency_stat'),
            ('Latência Máxima:', 'max_latency_stat'),
            ('Latência Média:', 'avg_latency_stat'),
            ('Perda de Pacotes Total:', 'packet_loss_total')
        ]
        
        for i, (label, key) in enumerate(stats_items):
            ttk.Label(summary_frame, text=label, font=('Segoe UI', 10)).grid(row=i//2, column=(i%2)*2, padx=20, pady=8, sticky='w')
            self.stats_labels[key] = ttk.Label(summary_frame, text='--', font=('Segoe UI', 11, 'bold'))
            self.stats_labels[key].grid(row=i//2, column=(i%2)*2+1, padx=20, pady=8, sticky='w')
    
    def create_logs_tab(self):
        control_frame = ttk.Frame(self.tab_logs)
        control_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(control_frame, text='📥 Exportar CSV', command=self.export_logs).pack(side='left', padx=5)
        ttk.Button(control_frame, text='🗑️ Limpar Logs', command=self.clear_logs).pack(side='left', padx=5)
        ttk.Button(control_frame, text='🔄 Atualizar', command=self.refresh_logs).pack(side='left', padx=5)
        
        self.log_text = scrolledtext.ScrolledText(self.tab_logs, wrap=tk.WORD, height=30, 
                                                   bg='#1e1e1e', fg='#ffffff', 
                                                   font=('Consolas', 9))
        self.log_text.pack(fill='both', expand=True, padx=10, pady=10)
    
    def create_config_tab(self):
        config_frame = ttk.LabelFrame(self.tab_config, text='Configurações do Monitor', padding=20)
        config_frame.pack(fill='both', padx=20, pady=20)
        
        ttk.Label(config_frame, text='Limiar de Alerta de Latência (ms):').grid(row=0, column=0, padx=10, pady=10, sticky='w')
        self.alert_threshold_spin = ttk.Spinbox(config_frame, from_=10, to=1000, increment=10, width=15)
        self.alert_threshold_spin.set(self.monitor.alert_threshold)
        self.alert_threshold_spin.grid(row=0, column=1, padx=10, pady=10)
        
        ttk.Label(config_frame, text='Limiar de Perda de Pacotes (%):').grid(row=1, column=0, padx=10, pady=10, sticky='w')
        self.packet_loss_spin = ttk.Spinbox(config_frame, from_=1, to=50, increment=1, width=15)
        self.packet_loss_spin.set(self.monitor.packet_loss_threshold)
        self.packet_loss_spin.grid(row=1, column=1, padx=10, pady=10)
        
        self.sound_alert_var = tk.BooleanVar(value=self.monitor.enable_sound_alerts)
        ttk.Checkbutton(config_frame, text='Ativar Alertas Sonoros', variable=self.sound_alert_var).grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky='w')
        
        self.visual_alert_var = tk.BooleanVar(value=self.monitor.enable_alerts)
        ttk.Checkbutton(config_frame, text='Ativar Alertas Visuais', variable=self.visual_alert_var).grid(row=3, column=0, columnspan=2, padx=10, pady=10, sticky='w')
        
        button_frame = ttk.Frame(config_frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=20)
        
        ttk.Button(button_frame, text='💾 Salvar Configurações', command=self.save_settings).pack(side='left', padx=5)
        ttk.Button(button_frame, text='🔄 Restaurar Padrões', command=self.restore_defaults).pack(side='left', padx=5)
        
        info_frame = ttk.LabelFrame(self.tab_config, text='Informações do Sistema', padding=20)
        info_frame.pack(fill='both', padx=20, pady=20)
        
        self.system_info_text = scrolledtext.ScrolledText(info_frame, wrap=tk.WORD, height=10,
                                                           bg='#1e1e1e', fg='#ffffff',
                                                           font=('Consolas', 9))
        self.system_info_text.pack(fill='both', expand=True)
        self.update_system_info()
    
    def on_server_change(self, event=None):
        server_name = self.server_combo.get()
        self.monitor.current_server = self.monitor.servers[server_name]
    
    def start_monitoring(self):
        try:
            self.monitor.interval = float(self.interval_spin.get())
            self.monitor.reset_stats()
            self.monitor.start_monitoring(self.on_monitor_data)
            
            self.start_btn.config(state='disabled')
            self.stop_btn.config(state='normal')
            self.server_combo.config(state='disabled')
            self.interval_spin.config(state='disabled')
            
            self.log_message("✅ Monitoramento iniciado!")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao iniciar monitoramento: {e}")
    
    def stop_monitoring(self):
        self.monitor.stop_monitoring()
        
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.server_combo.config(state='normal')
        self.interval_spin.config(state='normal')
        
        self.log_message("⏸️ Monitoramento parado.")
    
    def reset_data(self):
        if messagebox.askyesno("Confirmar", "Deseja resetar todos os dados?"):
            self.monitor.reset_stats()
            self.monitor.ping_history.clear()
            self.monitor.timestamps.clear()
            self.log_message("🔄 Dados resetados.")
    
    def on_monitor_data(self, data):
        if data.get('alert'):
            self.log_message(f"⚠️ {data['alert']}", level='warning')
        
        timestamp = data['timestamp'].strftime('%H:%M:%S')
        if data['status'] == 'success':
            latency = data['latency']
            self.log_message(f"[{timestamp}] Latência: {latency:.1f}ms", level='success')
        else:
            self.log_message(f"[{timestamp}] Falha na conexão!", level='error')
    
    def update_gui(self):
        try:
            if self.monitor.monitoring:
                self.status_labels['status'].config(text='🟢 Monitorando', foreground='#4ec9b0')
            else:
                self.status_labels['status'].config(text='🔴 Parado', foreground='#f48771')
            
            if len(self.monitor.ping_history) > 0:
                current = self.monitor.ping_history[-1]
                self.status_labels['current_latency'].config(text=f'{current:.1f} ms')
                
                min_lat = self.monitor.stats['min_latency']
                max_lat = self.monitor.stats['max_latency']
                avg_lat = self.monitor.stats['avg_latency']
                
                self.status_labels['min_latency'].config(text=f'{min_lat:.1f} ms' if min_lat != float('inf') else '--')
                self.status_labels['max_latency'].config(text=f'{max_lat:.1f} ms')
                self.status_labels['avg_latency'].config(text=f'{avg_lat:.1f} ms')
            
            self.status_labels['packet_loss'].config(text=f'{self.monitor.stats["packet_loss"]:.1f}%')
            
            self.update_graph()
            self.update_statistics()
            
        except Exception as e:
            print(f"Erro ao atualizar GUI: {e}")
        
        self.root.after(self.update_interval, self.update_gui)
    
    def update_graph(self):
        if len(self.monitor.ping_history) > 1:
            self.ax.clear()
            
            x_data = list(range(len(self.monitor.ping_history)))
            y_data = list(self.monitor.ping_history)
            
            self.ax.plot(x_data, y_data, color='#4ec9b0', linewidth=2)
            self.ax.fill_between(x_data, y_data, alpha=0.3, color='#4ec9b0')
            
            if self.monitor.alert_threshold:
                self.ax.axhline(y=self.monitor.alert_threshold, color='#f48771', linestyle='--', label='Limiar de Alerta')
            
            self.ax.set_xlabel('Amostras', color='white')
            self.ax.set_ylabel('Latência (ms)', color='white')
            self.ax.tick_params(colors='white')
            self.ax.set_facecolor('#1e1e1e')
            self.ax.grid(True, alpha=0.3)
            self.ax.legend(facecolor='#2d2d2d', edgecolor='white', labelcolor='white')
            
            self.canvas.draw()
    
    def update_statistics(self):
        stats = self.monitor.stats
        
        if stats['start_time']:
            uptime = datetime.now() - stats['start_time']
            self.stats_labels['uptime'].config(text=str(uptime).split('.')[0])
        
        self.stats_labels['total_pings'].config(text=str(stats['total_pings']))
        self.stats_labels['successful_pings'].config(text=str(stats['successful_pings']))
        self.stats_labels['failed_pings'].config(text=str(stats['failed_pings']))
        self.stats_labels['alerts_triggered'].config(text=str(stats['alerts_triggered']))
        
        if stats['total_pings'] > 0:
            success_rate = (stats['successful_pings'] / stats['total_pings']) * 100
            self.stats_labels['success_rate'].config(text=f'{success_rate:.1f}%')
        
        if stats['min_latency'] != float('inf'):
            self.stats_labels['min_latency_stat'].config(text=f'{stats["min_latency"]:.1f} ms')
        self.stats_labels['max_latency_stat'].config(text=f'{stats["max_latency"]:.1f} ms')
        self.stats_labels['avg_latency_stat'].config(text=f'{stats["avg_latency"]:.1f} ms')
        self.stats_labels['packet_loss_total'].config(text=f'{stats["packet_loss"]:.2f}%')
    
    def log_message(self, message, level='info'):
        self.log_text.insert(tk.END, f"{message}\\n")
        self.log_text.see(tk.END)
    
    def export_logs(self):
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
            )
            if filename:
                if os.path.exists(self.monitor.log_file):
                    import shutil
                    shutil.copy(self.monitor.log_file, filename)
                    messagebox.showinfo("Sucesso", f"Logs exportados para {filename}")
                else:
                    messagebox.showwarning("Aviso", "Nenhum log disponível para exportar")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao exportar logs: {e}")
    
    def clear_logs(self):
        if messagebox.askyesno("Confirmar", "Deseja limpar todos os logs?"):
            self.log_text.delete(1.0, tk.END)
            if os.path.exists(self.monitor.log_file):
                os.remove(self.monitor.log_file)
            self.log_message("🗑️ Logs limpos.")
    
    def refresh_logs(self):
        try:
            if os.path.exists(self.monitor.log_file):
                self.log_text.delete(1.0, tk.END)
                with open(self.monitor.log_file, 'r', encoding='utf-8') as f:
                    self.log_text.insert(tk.END, f.read())
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao atualizar logs: {e}")
    
    def save_settings(self):
        try:
            self.monitor.alert_threshold = float(self.alert_threshold_spin.get())
            self.monitor.packet_loss_threshold = float(self.packet_loss_spin.get())
            self.monitor.enable_sound_alerts = self.sound_alert_var.get()
            self.monitor.enable_alerts = self.visual_alert_var.get()
            
            self.monitor.save_config()
            messagebox.showinfo("Sucesso", "Configurações salvas com sucesso!")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao salvar configurações: {e}")
    
    def restore_defaults(self):
        if messagebox.askyesno("Confirmar", "Deseja restaurar as configurações padrão?"):
            self.alert_threshold_spin.set(100)
            self.packet_loss_spin.set(5)
            self.sound_alert_var.set(True)
            self.visual_alert_var.set(True)
            self.save_settings()
    
    def update_system_info(self):
        try:
            info = []
            info.append("=== INFORMAÇÕES DE REDE ===\\n")
            
            interfaces = self.monitor.get_network_interfaces()
            for iface in interfaces:
                info.append(f"Interface: {iface['name']}")
                info.append(f"  IP: {iface['ip']}")
                info.append(f"  Velocidade: {iface['speed']} Mbps\\n")
            
            net_io = psutil.net_io_counters()
            info.append(f"\\n=== ESTATÍSTICAS GLOBAIS ===")
            info.append(f"Bytes Enviados: {net_io.bytes_sent / (1024**3):.2f} GB")
            info.append(f"Bytes Recebidos: {net_io.bytes_recv / (1024**3):.2f} GB")
            info.append(f"Pacotes Enviados: {net_io.packets_sent:,}")
            info.append(f"Pacotes Recebidos: {net_io.packets_recv:,}")
            
            self.system_info_text.delete(1.0, tk.END)
            self.system_info_text.insert(tk.END, '\\n'.join(info))
        except Exception as e:
            self.system_info_text.insert(tk.END, f"Erro ao obter informações: {e}")


def main():
    root = tk.Tk()
    app = MonitorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
'''

def main():
    print("="*60)
    print("INSTALADOR DO MONITOR DE REDE PROFESSIONAL")
    print("="*60)
    
    # Salva o arquivo
    with open('monitoramento.py', 'w', encoding='utf-8') as f:
        f.write(MONITOR_CODE)
    
    print("\n✅ Arquivo 'monitoramento.py' criado com sucesso!")
    print("\n📦 Próximos passos:")
    print("   1. Instale as dependências: pip install -r requirements.txt")
    print("   2. Execute o monitor: python monitoramento.py")
    print("\n🎉 Instalação concluída!")
    print("="*60)

if __name__ == "__main__":
    main()
