
"""
Sistema Completo de Monitoramento de Rede - Windows
Versão: 2.0 Professional
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
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
import base64

# Cria pasta de logs se não existir
if not os.path.exists('logs'):
    os.makedirs('logs')


class NetworkMonitor:
    def __init__(self):
        self.monitoring = False
        self.data_queue = queue.Queue()
        # OTIMIZAÇÃO: Mantém apenas 200 amostras no gráfico (performance)
        # Mas contagem total é mantida em stats['total_pings']
        self.ping_history = deque(maxlen=200)
        self.timestamps = deque(maxlen=200)
        self.packet_loss_history = deque(maxlen=50)
        self.download_speed_history = deque(maxlen=30)
        self.ping_count_offset = 0  # Offset para mostrar número real no eixo X
        
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
        self.log_file = 'logs/network_monitor_log.csv'
        self.anomaly_file = 'logs/anomalias_detectadas.csv'
        self.enable_alerts = True
        self.enable_sound_alerts = True
        self.enable_auto_export = True
        
        # Sistema de detecção de anomalias
        self.anomaly_threshold = 100  # ms - threshold fixo
        self.anomaly_deviation_multiplier = 2.5  # Desvio padrão - detecta picos relativos
        self.anomaly_min_samples = 30  # Mínimo de pings para calcular desvio
        self.anomaly_min_consecutive_normal = 10  # Pings normais necessários para fechar anomalia
        self.anomaly_min_pings = 5  # FILTRO: Mínimo de pings afetados para registrar anomalia
        self.anomaly_window = []  # Pings durante anomalia
        self.anomaly_normal_buffer = []  # Buffer de pings normais temporários
        self.in_anomaly = False
        self.anomaly_start_time = None
        self.anomaly_start_index = 0
        self.detected_anomalies = []  # Lista de anomalias detectadas
        self.baseline_latencies = deque(maxlen=100)  # Últimas 100 latências para baseline
        
        # Cache para otimização
        self.cached_baseline_mean = None
        self.cached_baseline_stdev = None
        self.baseline_cache_count = 0
        
        # Buffer para batch write (otimiza I/O de disco)
        self.log_buffer = []
        self.log_buffer_max = 10  # Escreve a cada 10 pings
        
        self.load_config()
        self.load_anomalies()
    
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
    
    def get_default_gateway(self):
        """Detecta o gateway padrão (roteador conectado)"""
        try:
            result = subprocess.run(
                ['ipconfig'],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            lines = result.stdout.split('\n')
            for i, line in enumerate(lines):
                if 'Gateway Padrão' in line or 'Default Gateway' in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        gateway = parts[1].strip()
                        if gateway and gateway != '':
                            return gateway
            return None
        except Exception as e:
            print(f"Erro ao detectar gateway: {e}")
            return None
    
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
                    
                    # DETECTOR DE ANOMALIAS
                    self.detect_anomaly(latency, timestamp)
                    
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
                
                # Log PERMANENTE em arquivo a cada ping (histórico completo para provas)
                self.log_to_file(timestamp, latency)
                
                elapsed = time.time() - start_time
                sleep_time = max(0, self.interval - elapsed)
                time.sleep(sleep_time)
                
            except Exception as e:
                print(f"Erro no loop de monitoramento: {e}")
                time.sleep(self.interval)
    
    def log_to_file(self, timestamp, latency):
        """
        Salva TODOS os pings em arquivos CSV com rotação diária.
        OTIMIZADO: Usa buffer para escrever em lotes (reduz I/O de disco)
        """
        try:
            # Prepara dados
            status = 'Success' if latency is not None else 'Failed'
            latency_str = f'{latency:.2f}' if latency is not None else 'N/A'
            packet_loss = f'{self.stats["packet_loss"]:.2f}'
            
            log_entry = {
                'timestamp': timestamp,
                'server': self.current_server,
                'latency_str': latency_str,
                'status': status,
                'packet_loss': packet_loss
            }
            
            # Adiciona ao buffer
            self.log_buffer.append(log_entry)
            
            # Escreve apenas quando buffer está cheio (batch write)
            if len(self.log_buffer) >= self.log_buffer_max:
                self.flush_log_buffer()
                
        except Exception as e:
            print(f"Erro ao preparar log: {e}")
    
    def flush_log_buffer(self):
        """Escreve buffer de logs no disco de uma vez (otimizado)"""
        if not self.log_buffer:
            return
        
        try:
            current_date = self.log_buffer[0]['timestamp'].strftime('%Y-%m-%d')
            log_filename = f'logs/network_log_{current_date}.csv'
            
            file_exists = os.path.exists(log_filename)
            with open(log_filename, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(['Timestamp', 'Server', 'Latency (ms)', 'Status', 'Packet_Loss_%'])
                
                # Escreve todos os logs do buffer de uma vez
                for entry in self.log_buffer:
                    writer.writerow([
                        entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                        entry['server'],
                        entry['latency_str'],
                        entry['status'],
                        entry['packet_loss']
                    ])
            
            self.log_buffer.clear()
        except Exception as e:
            print(f"Erro ao salvar logs em lote: {e}")
    
    def start_monitoring(self, callback):
        if not self.monitoring:
            self.monitoring = True
            thread = threading.Thread(target=self.monitor_loop, args=(callback,), daemon=True)
            thread.start()
    
    def stop_monitoring(self):
        self.monitoring = False
        # Garante que logs pendentes sejam salvos
        self.flush_log_buffer()
    
    def detect_anomaly(self, latency, timestamp):
        """
        Detecta e registra períodos de anomalia (latência alta).
        
        Sistema HÍBRIDO inteligente com dois métodos de detecção:
        
        1) THRESHOLD FIXO: latência >= 100ms (sempre anômalo)
        2) DESVIO ESTATÍSTICO: latência >> média + (desvio_padrão * 2.5)
           Exemplo: se média=30ms e desvio=5ms, detecta acima de 42.5ms
        
        Buffer de confirmação evita fragmentação de anomalias.
        """
        # Adiciona à baseline (histórico de latências normais)
        if not self.in_anomaly:
            self.baseline_latencies.append(latency)
            self.baseline_cache_count += 1
        
        # Calcula se é anomalia usando DOIS critérios
        is_anomaly = False
        anomaly_reason = ""
        
        # CRITÉRIO 1: Threshold fixo (sempre funciona)
        if latency >= self.anomaly_threshold:
            is_anomaly = True
            anomaly_reason = f"threshold fixo ({self.anomaly_threshold}ms)"
        
        # CRITÉRIO 2: Desvio estatístico (mais sensível após ter dados suficientes)
        elif len(self.baseline_latencies) >= self.anomaly_min_samples:
            # OTIMIZAÇÃO: Recalcula baseline apenas a cada 10 pings (reduz CPU em 90%)
            if self.baseline_cache_count >= 10 or self.cached_baseline_mean is None:
                self.cached_baseline_mean = statistics.mean(self.baseline_latencies)
                self.cached_baseline_stdev = statistics.stdev(self.baseline_latencies)
                self.baseline_cache_count = 0
            
            baseline_mean = self.cached_baseline_mean
            baseline_stdev = self.cached_baseline_stdev
            
            # Threshold dinâmico baseado em desvio padrão
            dynamic_threshold = baseline_mean + (baseline_stdev * self.anomaly_deviation_multiplier)
            
            if latency > dynamic_threshold:
                is_anomaly = True
                anomaly_reason = f"desvio estatístico (média={baseline_mean:.1f}ms, limite={dynamic_threshold:.1f}ms)"
        
        # DETECTOU ANOMALIA
        if is_anomaly:
            if not self.in_anomaly:
                # INÍCIO de uma anomalia
                self.in_anomaly = True
                self.anomaly_start_time = timestamp
                self.anomaly_start_index = self.stats['total_pings']
                self.anomaly_window = [latency]
                self.anomaly_normal_buffer = []
                self.anomaly_reason = anomaly_reason
                print(f"🚨 ANOMALIA DETECTADA: {latency:.1f}ms ({anomaly_reason})")
            else:
                # Anomalia continua
                self.anomaly_window.append(latency)
                
                # Se tinha pings normais no buffer, adiciona eles também
                if self.anomaly_normal_buffer:
                    self.anomaly_window.extend(self.anomaly_normal_buffer)
                    self.anomaly_normal_buffer = []
        
        # LATÊNCIA NORMAL
        else:
            if self.in_anomaly:
                # Adiciona ao buffer de confirmação
                self.anomaly_normal_buffer.append(latency)
                
                # Verifica se tem pings normais suficientes para fechar
                if len(self.anomaly_normal_buffer) >= self.anomaly_min_consecutive_normal:
                    # FIM CONFIRMADO da anomalia - verificar se é significativa
                    self.in_anomaly = False
                    
                    pings_affected = len(self.anomaly_window)
                    
                    # FILTRO: Só registra anomalias com mínimo de pings afetados (padrão: 5)
                    if pings_affected >= self.anomaly_min_pings:
                        end_time = timestamp
                        duration = (end_time - self.anomaly_start_time).total_seconds()
                        avg_latency_anomaly = statistics.mean(self.anomaly_window)
                        max_latency_anomaly = max(self.anomaly_window)
                        min_latency_anomaly = min(self.anomaly_window)
                        
                        # Calcula baseline (latência normal ANTES da anomalia)
                        baseline_avg = 0
                        baseline_min = 0
                        baseline_max = 0
                        increase_percent = 0
                        
                        if len(self.baseline_latencies) >= 10:
                            # Usa últimas 50 latências normais como baseline
                            baseline_list = list(self.baseline_latencies)[-50:]
                            baseline_avg = statistics.mean(baseline_list)
                            baseline_min = min(baseline_list)
                            baseline_max = max(baseline_list)
                            
                            # Calcula quanto aumentou em %
                            if baseline_avg > 0:
                                increase_percent = ((avg_latency_anomaly - baseline_avg) / baseline_avg) * 100
                        
                        anomaly_data = {
                            'start_time': self.anomaly_start_time,
                            'end_time': end_time,
                            'duration_seconds': duration,
                            'avg_latency': avg_latency_anomaly,
                            'max_latency': max_latency_anomaly,
                            'min_latency': min_latency_anomaly,
                            'pings_affected': pings_affected,
                            'start_ping_number': self.anomaly_start_index,
                            'detection_method': getattr(self, 'anomaly_reason', 'threshold'),
                            'baseline_avg': baseline_avg,
                            'baseline_min': baseline_min,
                            'baseline_max': baseline_max,
                            'increase_percent': increase_percent
                        }
                        
                        self.detected_anomalies.append(anomaly_data)
                        self.save_anomaly(anomaly_data)
                        
                        print(f"✅ Anomalia registrada: {duration:.1f}s, {pings_affected} pings, média {avg_latency_anomaly:.1f}ms (baseline: {baseline_during})")
                    else:
                        # Anomalia muito curta - descarta
                        print(f"⏭️ Anomalia descartada: apenas {pings_affected} ping(s) afetado(s) - mínimo necessário: {self.anomaly_min_pings}")
                    
                    # Limpa buffers
                    self.anomaly_window = []
                    self.anomaly_normal_buffer = []
    
    def save_anomaly(self, anomaly_data):
        """Salva anomalia detectada em arquivo CSV"""
        try:
            file_exists = os.path.exists(self.anomaly_file)
            with open(self.anomaly_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow([
                        'Data', 'Hora_Inicio', 'Hora_Fim', 'Duracao_Segundos', 
                        'Latencia_Media_Pico', 'Latencia_Min_Pico', 'Latencia_Max_Pico', 
                        'Pings_Afetados', 'Numero_Ping_Inicio', 'Metodo_Deteccao', 
                        'Baseline_Media', 'Baseline_Min', 'Baseline_Max', 'Aumento_Percentual'
                    ])
                
                writer.writerow([
                    anomaly_data['start_time'].strftime('%Y-%m-%d'),
                    anomaly_data['start_time'].strftime('%H:%M:%S'),
                    anomaly_data['end_time'].strftime('%H:%M:%S'),
                    f"{anomaly_data['duration_seconds']:.2f}",
                    f"{anomaly_data['avg_latency']:.2f}",
                    f"{anomaly_data['min_latency']:.2f}",
                    f"{anomaly_data['max_latency']:.2f}",
                    anomaly_data['pings_affected'],
                    anomaly_data['start_ping_number'],
                    anomaly_data.get('detection_method', 'threshold'),
                    f"{anomaly_data.get('baseline_avg', 0):.2f}" if anomaly_data.get('baseline_avg', 0) > 0 else 'N/A',
                    f"{anomaly_data.get('baseline_min', 0):.2f}" if anomaly_data.get('baseline_min', 0) > 0 else 'N/A',
                    f"{anomaly_data.get('baseline_max', 0):.2f}" if anomaly_data.get('baseline_max', 0) > 0 else 'N/A',
                    f"{anomaly_data.get('increase_percent', 0):.1f}%" if anomaly_data.get('increase_percent', 0) > 0 else 'N/A'
                ])
        except Exception as e:
            print(f"Erro ao salvar anomalia: {e}")
    
    def load_anomalies(self):
        """Carrega anomalias já detectadas do arquivo"""
        try:
            if os.path.exists(self.anomaly_file):
                with open(self.anomaly_file, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        self.detected_anomalies.append(row)
        except Exception as e:
            print(f"Erro ao carregar anomalias: {e}")
    
    def reset_stats(self):
        """Reseta apenas as estatísticas da sessão atual, mantém logs permanentes"""
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
        self.ping_count_offset = 0
        # NÃO reseta anomalias detectadas - são permanentes
    
    def get_all_log_files(self):
        """Retorna lista de todos os arquivos de log disponíveis"""
        log_files = []
        if os.path.exists('logs'):
            for filename in os.listdir('logs'):
                if filename.startswith('network_log_') and filename.endswith('.csv'):
                    log_files.append(os.path.join('logs', filename))
        return sorted(log_files, reverse=True)
    
    def consolidate_logs(self, output_file='network_log_CONSOLIDATED.csv'):
        """Consolida todos os logs diários em um único arquivo para análise"""
        try:
            log_files = self.get_all_log_files()
            if not log_files:
                return False, "Nenhum arquivo de log encontrado"
            
            all_rows = []
            header_written = False
            
            for log_file in reversed(log_files):  # Do mais antigo para o mais novo
                with open(log_file, 'r', encoding='utf-8') as f:
                    reader = csv.reader(f)
                    rows = list(reader)
                    if rows:
                        if not header_written:
                            all_rows.append(rows[0])  # Header
                            header_written = True
                        all_rows.extend(rows[1:])  # Dados
            
            output_path = f'logs/{output_file}'
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerows(all_rows)
            
            return True, f"Consolidado com sucesso: {len(all_rows)-1} registros em {output_path}"
        except Exception as e:
            return False, f"Erro ao consolidar logs: {e}"
    
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
        # OTIMIZAÇÃO: Intervalo de atualização aumentado para 1000ms (menos lag)
        self.update_interval = 1000
        # Contador para atualização do gráfico (só atualiza a cada 5 ciclos)
        self.graph_update_counter = 0
        # Cache para evitar recálculos
        self.last_baseline_calc = 0
        
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
        
        self.tab_anomalies = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_anomalies, text='⚠️ Anomalias')
        self.create_anomalies_tab()
        
        self.tab_logs = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_logs, text='📋 Logs')
        self.create_logs_tab()
        
        self.tab_config = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_config, text='⚙️ Configurações')
        self.create_config_tab()
        
        self.tab_wifi = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_wifi, text='📡 Multi-Redes WiFi')
        self.create_wifi_tab()
    
    def create_monitor_tab(self):
        control_frame = ttk.LabelFrame(self.tab_monitor, text='Controles', padding=10)
        control_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(control_frame, text='Servidor:').grid(row=0, column=0, padx=5, pady=5, sticky='w')
        
        # Filtra servidores válidos (remove separador)
        valid_servers = {k: v for k, v in self.monitor.servers.items() if v is not None}
        self.server_combo = ttk.Combobox(control_frame, values=list(valid_servers.keys()), width=25)
        self.server_combo.set('Google DNS')
        self.server_combo.grid(row=0, column=1, padx=5, pady=5)
        self.server_combo.bind('<<ComboboxSelected>>', self.on_server_change)
        
        ttk.Label(control_frame, text='Intervalo (s):').grid(row=0, column=2, padx=5, pady=5, sticky='w')
        self.interval_spin = ttk.Spinbox(control_frame, from_=0.01, to=60, increment=0.5, width=10)
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
    
    def create_anomalies_tab(self):
        """Aba dedicada a mostrar APENAS períodos de instabilidade"""
        control_frame = ttk.Frame(self.tab_anomalies)
        control_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(control_frame, text='🔄 Atualizar', command=self.refresh_anomalies).pack(side='left', padx=5)
        ttk.Button(control_frame, text='📁 Exportar Relatório', command=self.export_anomalies).pack(side='left', padx=5)
        ttk.Button(control_frame, text='📂 Abrir CSV', command=self.open_anomaly_file).pack(side='left', padx=5)
        ttk.Button(control_frame, text='🗑️ Limpar Tudo', command=self.clear_anomalies).pack(side='left', padx=5)
        
        # Seletor de arquivo de anomalias
        selector_frame = ttk.Frame(self.tab_anomalies)
        selector_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(selector_frame, text='📊 Visualizar anomalias de:', font=('Segoe UI', 9, 'bold')).pack(side='left', padx=5)
        
        self.anomaly_file_combo = ttk.Combobox(selector_frame, width=50, state='readonly')
        self.anomaly_file_combo.pack(side='left', padx=5)
        self.anomaly_file_combo.bind('<<ComboboxSelected>>', self.on_anomaly_file_selected)
        
        ttk.Button(selector_frame, text='🔍 Atualizar Lista', 
                  command=self.update_anomaly_file_list).pack(side='left', padx=5)
        
        # Info sobre anomalias
        info_frame = ttk.LabelFrame(self.tab_anomalies, text='⚠️ Detector de Instabilidades', padding=10)
        info_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(info_frame, text='Sistema automático que registra APENAS períodos problemáticos:', 
                  font=('Segoe UI', 9, 'bold')).pack(anchor='w', pady=2)
        ttk.Label(info_frame, text='✓ Início e fim exatos (data/hora)', 
                  font=('Segoe UI', 9)).pack(anchor='w', padx=20)
        ttk.Label(info_frame, text='✓ Duração do problema (segundos)', 
                  font=('Segoe UI', 9)).pack(anchor='w', padx=20)
        ttk.Label(info_frame, text='✓ Latência média SOMENTE durante o pico', 
                  font=('Segoe UI', 9)).pack(anchor='w', padx=20)
        ttk.Label(info_frame, text='✓ Latência máxima atingida', 
                  font=('Segoe UI', 9)).pack(anchor='w', padx=20)
        ttk.Label(info_frame, text='✓ Quantos pings foram afetados', 
                  font=('Segoe UI', 9)).pack(anchor='w', padx=20)
        
        self.anomaly_info_label = ttk.Label(info_frame, text='', font=('Segoe UI', 9, 'bold'), foreground='#f48771')
        self.anomaly_info_label.pack(pady=5)
        
        # Tabela de anomalias
        self.anomaly_text = scrolledtext.ScrolledText(self.tab_anomalies, wrap=tk.NONE, height=25, 
                                                       bg='#1e1e1e', fg='#ffffff', 
                                                       font=('Consolas', 9))
        self.anomaly_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Inicializa arquivo atual como None (usará padrão)
        self.current_anomaly_file = None
        
        # Carrega anomalias
        self.refresh_anomalies()
    
    def create_logs_tab(self):
        control_frame = ttk.Frame(self.tab_logs)
        control_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(control_frame, text='� Exportar Logs', command=self.export_logs).pack(side='left', padx=5)
        ttk.Button(control_frame, text='� Consolidar Todos', command=self.consolidate_all_logs).pack(side='left', padx=5)
        ttk.Button(control_frame, text='📂 Abrir Pasta Logs', command=self.open_logs_folder).pack(side='left', padx=5)
        ttk.Button(control_frame, text='🔄 Atualizar', command=self.refresh_logs).pack(side='left', padx=5)
        ttk.Button(control_frame, text='🗑️ Limpar Visual', command=self.clear_logs).pack(side='left', padx=5)
        
        # Info sobre logs permanentes
        info_frame = ttk.LabelFrame(self.tab_logs, text='📦 Sistema de Logs Permanentes', padding=5)
        info_frame.pack(fill='x', padx=10, pady=5)
        
        self.log_info_label = ttk.Label(info_frame, text='Carregando informações...', font=('Segoe UI', 9))
        self.log_info_label.pack(pady=5)
        
        self.log_text = scrolledtext.ScrolledText(self.tab_logs, wrap=tk.WORD, height=30, 
                                                   bg='#1e1e1e', fg='#ffffff', 
                                                   font=('Consolas', 9))
        self.log_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Atualizar info de logs
        self.update_log_info()
    
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
        
        ttk.Label(config_frame, text='Pings normais para fechar anomalia:').grid(row=2, column=0, padx=10, pady=10, sticky='w')
        self.anomaly_buffer_spin = ttk.Spinbox(config_frame, from_=3, to=30, increment=1, width=15)
        self.anomaly_buffer_spin.set(self.monitor.anomaly_min_consecutive_normal)
        self.anomaly_buffer_spin.grid(row=2, column=1, padx=10, pady=10)
        ttk.Label(config_frame, text='(evita fragmentar oscilações rápidas)', 
                  font=('Segoe UI', 8), foreground='gray').grid(row=2, column=2, padx=5, sticky='w')
        
        # NOVA OPÇÃO: Sensibilidade de detecção por desvio
        ttk.Label(config_frame, text='Sensibilidade detecção (desvios):').grid(row=3, column=0, padx=10, pady=10, sticky='w')
        self.anomaly_deviation_spin = ttk.Spinbox(config_frame, from_=1.5, to=5.0, increment=0.5, width=15)
        self.anomaly_deviation_spin.set(self.monitor.anomaly_deviation_multiplier)
        self.anomaly_deviation_spin.grid(row=3, column=1, padx=10, pady=10)
        ttk.Label(config_frame, text='(menor=mais sensível, 2.5=padrão)', 
                  font=('Segoe UI', 8), foreground='gray').grid(row=3, column=2, padx=5, sticky='w')
        
        # NOVA OPÇÃO: Mínimo de pings para registrar anomalia
        ttk.Label(config_frame, text='Mínimo de pings afetados:').grid(row=4, column=0, padx=10, pady=10, sticky='w')
        self.anomaly_min_pings_spin = ttk.Spinbox(config_frame, from_=1, to=30, increment=1, width=15)
        self.anomaly_min_pings_spin.set(self.monitor.anomaly_min_pings)
        self.anomaly_min_pings_spin.grid(row=4, column=1, padx=10, pady=10)
        ttk.Label(config_frame, text='(ignora picos muito curtos, 5=padrão)', 
                  font=('Segoe UI', 8), foreground='gray').grid(row=4, column=2, padx=5, sticky='w')
        
        self.sound_alert_var = tk.BooleanVar(value=self.monitor.enable_sound_alerts)
        ttk.Checkbutton(config_frame, text='Ativar Alertas Sonoros', variable=self.sound_alert_var).grid(row=5, column=0, columnspan=2, padx=10, pady=10, sticky='w')
        
        self.visual_alert_var = tk.BooleanVar(value=self.monitor.enable_alerts)
        ttk.Checkbutton(config_frame, text='Ativar Alertas Visuais', variable=self.visual_alert_var).grid(row=6, column=0, columnspan=2, padx=10, pady=10, sticky='w')
        
        button_frame = ttk.Frame(config_frame)
        button_frame.grid(row=7, column=0, columnspan=2, pady=20)
        
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
        if server_name in self.monitor.servers:
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
            # OTIMIZAÇÃO: Atualiza status apenas se monitorando
            if self.monitor.monitoring:
                self.status_labels['status'].config(text='🟢 Monitorando', foreground='#4ec9b0')
            else:
                self.status_labels['status'].config(text='🔴 Parado', foreground='#f48771')
            
            # OTIMIZAÇÃO: Só atualiza se tiver dados
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
            
            # OTIMIZAÇÃO: Atualiza gráfico apenas a cada 5 ciclos (reduz CPU em 80%)
            self.graph_update_counter += 1
            if self.graph_update_counter >= 5:
                self.update_graph()
                self.graph_update_counter = 0
            
            # OTIMIZAÇÃO: Atualiza estatísticas apenas a cada 3 ciclos
            if self.graph_update_counter % 3 == 0:
                self.update_statistics()
            
            # CORREÇÃO: Atualiza contador de anomalias SEMPRE (não só quando na aba)
            if hasattr(self, 'last_anomaly_count'):
                if len(self.monitor.detected_anomalies) != self.last_anomaly_count:
                    self.refresh_anomalies()
                    self.last_anomaly_count = len(self.monitor.detected_anomalies)
            else:
                self.last_anomaly_count = len(self.monitor.detected_anomalies)
            
        except Exception as e:
            print(f"Erro ao atualizar GUI: {e}")
        
        self.root.after(self.update_interval, self.update_gui)
    
    def update_graph(self):
        # OTIMIZAÇÃO: Só atualiza se tiver dados suficientes e estiver monitorando
        if len(self.monitor.ping_history) > 1 and self.monitor.monitoring:
            self.ax.clear()
            
            # Calcula offset para mostrar números reais no eixo X
            total_pings = self.monitor.stats['total_pings']
            samples_shown = len(self.monitor.ping_history)
            
            # Se tiver mais pings que o buffer, calcula offset
            if total_pings > samples_shown:
                self.monitor.ping_count_offset = total_pings - samples_shown
            
            # Eixo X mostra números reais (não resetados)
            x_data = [self.monitor.ping_count_offset + i for i in range(samples_shown)]
            y_data = list(self.monitor.ping_history)
            
            self.ax.plot(x_data, y_data, color='#4ec9b0', linewidth=1.5, marker='', linestyle='-')
            
            if self.monitor.alert_threshold:
                self.ax.axhline(y=self.monitor.alert_threshold, color='#f48771', linestyle='--', linewidth=1, label='Limiar')
            
            # Label informativo mostrando range
            if total_pings > samples_shown:
                xlabel = f'Pings (mostrando últimos {samples_shown} de {total_pings} total)'
            else:
                xlabel = f'Pings ({total_pings} total)'
            
            self.ax.set_xlabel(xlabel, color='white', fontsize=9)
            self.ax.set_ylabel('Latência (ms)', color='white', fontsize=9)
            self.ax.tick_params(colors='white', labelsize=8)
            self.ax.set_facecolor('#1e1e1e')
            self.ax.grid(True, alpha=0.2, linewidth=0.5)
            self.ax.legend(facecolor='#2d2d2d', edgecolor='white', labelcolor='white', fontsize=8)
            
            # OTIMIZAÇÃO: draw_idle() é mais rápido que draw()
            self.canvas.draw_idle()
    
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
        # OTIMIZAÇÃO: Limita log visual a 500 linhas para não travar
        line_count = int(self.log_text.index('end-1c').split('.')[0])
        if line_count > 500:
            self.log_text.delete('1.0', '100.0')  # Remove primeiras 100 linhas
        
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
    
    def get_all_anomaly_files(self):
        """Retorna lista de todos os arquivos de anomalias disponíveis"""
        anomaly_files = []
        if os.path.exists('logs'):
            for filename in os.listdir('logs'):
                if filename.startswith('anomalias_') and filename.endswith('.csv'):
                    full_path = os.path.join('logs', filename)
                    # Extrai info do nome: anomalias_REDE_DATA.csv
                    parts = filename.replace('anomalias_', '').replace('.csv', '').split('_')
                    if len(parts) >= 2:
                        date = parts[-1]  # Última parte é a data
                        network = '_'.join(parts[:-1])  # Resto é o nome da rede
                        display_name = f"{network} ({date})"
                    else:
                        display_name = filename.replace('anomalias_', '').replace('.csv', '')
                    
                    anomaly_files.append((display_name, full_path))
        
        # Ordena por data (mais recente primeiro)
        return sorted(anomaly_files, key=lambda x: x[1], reverse=True)
    
    def update_anomaly_file_list(self):
        """Atualiza lista de arquivos de anomalias no combobox"""
        files = self.get_all_anomaly_files()
        
        if files:
            display_names = [name for name, _ in files]
            self.anomaly_file_combo['values'] = display_names
            
            # Seleciona o mais recente por padrão
            if not self.anomaly_file_combo.get() or self.anomaly_file_combo.get() not in display_names:
                self.anomaly_file_combo.current(0)
            
            self.wifi_log_message(f"📋 {len(files)} arquivo(s) de anomalias encontrado(s)")
        else:
            self.anomaly_file_combo['values'] = ['Nenhum arquivo encontrado']
            self.anomaly_file_combo.current(0)
    
    def on_anomaly_file_selected(self, event=None):
        """Quando usuário seleciona um arquivo de anomalias diferente"""
        selected_display = self.anomaly_file_combo.get()
        
        # Encontra o caminho real do arquivo
        files = self.get_all_anomaly_files()
        for display_name, file_path in files:
            if display_name == selected_display:
                self.current_anomaly_file = file_path
                self.refresh_anomalies()
                break
    
    def refresh_anomalies(self):
        """Atualiza a exibição de anomalias detectadas"""
        try:
            # Atualiza lista de arquivos disponíveis
            self.update_anomaly_file_list()
            
            self.anomaly_text.delete(1.0, tk.END)
            
            # Usa arquivo selecionado ou padrão
            file_to_read = getattr(self, 'current_anomaly_file', self.monitor.anomaly_file)
            
            if not os.path.exists(file_to_read):
                self.anomaly_text.insert(tk.END, "✅ Nenhuma anomalia detectada ainda.\n\n")
                self.anomaly_text.insert(tk.END, "O sistema está monitorando e registrará automaticamente:\n")
                self.anomaly_text.insert(tk.END, "• Picos de latência acima de 100ms (mínimo 5 pings)\n")
                self.anomaly_text.insert(tk.END, "• Data/hora exata do problema\n")
                self.anomaly_text.insert(tk.END, "• Duração do problema\n")
                self.anomaly_text.insert(tk.END, "• Latência média durante o pico\n")
                self.anomaly_info_label.config(text="Sistema ativo - aguardando anomalias")
                return
            
            with open(file_to_read, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
            if len(lines) <= 1:
                self.anomaly_text.insert(tk.END, "✅ Nenhuma anomalia detectada ainda.\n")
                self.anomaly_info_label.config(text="Sistema ativo - aguardando anomalias")
                return
            
            # Header formatado
            self.anomaly_text.insert(tk.END, "═══════════════════════════════════════════════════════════════════════════\n")
            self.anomaly_text.insert(tk.END, "              RELATÓRIO DE ANOMALIAS DE REDE DETECTADAS\n")
            self.anomaly_text.insert(tk.END, "═══════════════════════════════════════════════════════════════════════════\n\n")
            
            anomaly_count = 0
            for i, line in enumerate(lines[1:], 1):  # Pula header
                parts = line.strip().split(',')
                if len(parts) >= 9:
                    anomaly_count += 1
                    self.anomaly_text.insert(tk.END, f"╔═══ ANOMALIA #{anomaly_count} ═══════════════════════════════════════════════╗\n")
                    self.anomaly_text.insert(tk.END, f"║ 📅 Data:        {parts[0]}\n")
                    self.anomaly_text.insert(tk.END, f"║ ⏰ Início:      {parts[1]}\n")
                    self.anomaly_text.insert(tk.END, f"║ ⏱️  Fim:         {parts[2]}\n")
                    self.anomaly_text.insert(tk.END, f"║ ⌛ Duração:     {parts[3]} segundos\n")
                    self.anomaly_text.insert(tk.END, f"║\n")
                    
                    # Verifica se tem dados de baseline (arquivos novos vs antigos)
                    if len(parts) >= 14 and parts[10] != 'N/A':
                        # Arquivo novo com baseline completo
                        self.anomaly_text.insert(tk.END, f"║ 📊 LATÊNCIA NORMAL (antes da anomalia):\n")
                        self.anomaly_text.insert(tk.END, f"║    • Média:  {parts[10]} ms\n")
                        self.anomaly_text.insert(tk.END, f"║    • Mínima: {parts[11]} ms\n")
                        self.anomaly_text.insert(tk.END, f"║    • Máxima: {parts[12]} ms\n")
                        self.anomaly_text.insert(tk.END, f"║\n")
                        self.anomaly_text.insert(tk.END, f"║ 🔥 LATÊNCIA DURANTE O PICO:\n")
                        self.anomaly_text.insert(tk.END, f"║    • Média:  {parts[4]} ms\n")
                        self.anomaly_text.insert(tk.END, f"║    • Mínima: {parts[5]} ms\n")
                        self.anomaly_text.insert(tk.END, f"║    • Máxima: {parts[6]} ms\n")
                        self.anomaly_text.insert(tk.END, f"║\n")
                        self.anomaly_text.insert(tk.END, f"║ 📈 Aumento:    {parts[13]}\n")
                    elif len(parts) >= 11 and parts[10] != 'N/A':
                        # Arquivo antigo com apenas baseline_media
                        self.anomaly_text.insert(tk.END, f"║ 📊 Baseline:   {parts[10]} (média normal)\n")
                        self.anomaly_text.insert(tk.END, f"║ 🔥 Pico Médio: {parts[4]} ms\n")
                        self.anomaly_text.insert(tk.END, f"║ 📉 Pico Mín:   {parts[5]} ms\n")
                        self.anomaly_text.insert(tk.END, f"║ 📈 Pico Máx:   {parts[6]} ms\n")
                    else:
                        # Arquivo muito antigo sem baseline
                        self.anomaly_text.insert(tk.END, f"║ 🔥 Latência Média: {parts[4]} ms (média durante pico)\n")
                        self.anomaly_text.insert(tk.END, f"║ 📉 Latência Mín:   {parts[5]} ms\n")
                        self.anomaly_text.insert(tk.END, f"║ 📈 Latência Máx:   {parts[6]} ms\n")
                    
                    self.anomaly_text.insert(tk.END, f"║\n")
                    self.anomaly_text.insert(tk.END, f"║ 📍 Pings Afetados: {parts[7]}\n")
                    self.anomaly_text.insert(tk.END, f"║ 🔢 Ping Número:    {parts[8]}\n")
                    
                    # Método de detecção se disponível
                    if len(parts) >= 10:
                        method = parts[9] if parts[9] else 'threshold'
                        self.anomaly_text.insert(tk.END, f"║ 🔍 Método:         {method}\n")
                    
                    self.anomaly_text.insert(tk.END, f"╚════════════════════════════════════════════════════════════════════════════╝\n\n")
            
            # Extrai nome da rede do arquivo
            file_basename = os.path.basename(file_to_read)
            self.anomaly_info_label.config(
                text=f"⚠️ {anomaly_count} anomalia(s) em: {file_basename}"
            )
            
        except Exception as e:
            self.anomaly_text.insert(tk.END, f"Erro ao carregar anomalias: {e}\n")
    
    def export_anomalies(self):
        """Exporta relatório de anomalias"""
        try:
            if not os.path.exists(self.monitor.anomaly_file):
                messagebox.showinfo("Info", "Nenhuma anomalia detectada ainda.")
                return
            
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                initialfile="relatorio_anomalias.csv"
            )
            if filename:
                import shutil
                shutil.copy(self.monitor.anomaly_file, filename)
                messagebox.showinfo("Sucesso", f"Relatório de anomalias exportado para:\n{filename}")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao exportar: {e}")
    
    def open_anomaly_file(self):
        """Abre arquivo de anomalias no Excel/editor padrão"""
        try:
            if os.path.exists(self.monitor.anomaly_file):
                os.startfile(self.monitor.anomaly_file)
            else:
                messagebox.showinfo("Info", "Nenhuma anomalia detectada ainda.")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao abrir arquivo: {e}")
    
    def clear_anomalies(self):
        """Limpa histórico de anomalias"""
        # Pergunta qual opção
        result = messagebox.askquestion(
            "Escolha a Ação", 
            "O que você deseja limpar?\n\n"
            "• SIM = Apenas o arquivo ATUAL visualizado\n"
            "• NÃO = TODOS os arquivos de anomalias\n"
            "• CANCELAR = Não fazer nada",
            icon='warning',
            type=messagebox.YESNOCANCEL
        )
        
        if result == 'cancel':
            return
        
        try:
            if result == 'yes':
                # Limpa APENAS o arquivo atual
                file_to_delete = getattr(self, 'current_anomaly_file', self.monitor.anomaly_file)
                
                if os.path.exists(file_to_delete):
                    os.remove(file_to_delete)
                    file_name = os.path.basename(file_to_delete)
                    messagebox.showinfo("Sucesso", f"Arquivo removido:\n{file_name}")
                else:
                    messagebox.showinfo("Info", "Arquivo não existe ou já foi removido.")
                
            else:
                # Limpa TODOS os arquivos de anomalias
                if messagebox.askyesno("⚠️ CONFIRMAÇÃO FINAL", 
                                      "Tem certeza que deseja DELETAR TODOS os arquivos de anomalias?\n\n"
                                      "Isso irá apagar:\n"
                                      "• Todas as redes testadas\n"
                                      "• Todos os dias de histórico\n\n"
                                      "⚠️ ESTA AÇÃO NÃO PODE SER DESFEITA!"):
                    
                    deleted_count = 0
                    if os.path.exists('logs'):
                        for filename in os.listdir('logs'):
                            if filename.startswith('anomalias_') and filename.endswith('.csv'):
                                file_path = os.path.join('logs', filename)
                                os.remove(file_path)
                                deleted_count += 1
                    
                    messagebox.showinfo("Sucesso", f"✅ {deleted_count} arquivo(s) de anomalias removido(s)!")
            
            # Limpa memória e atualiza interface
            self.monitor.detected_anomalies = []
            self.current_anomaly_file = None
            self.refresh_anomalies()
            
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao limpar: {e}")
    
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
        """Limpa apenas a visualização de logs na interface (não apaga arquivos CSV)"""
        if messagebox.askyesno("Confirmar", "Limpar visualização de logs?\n\n⚠️ Os arquivos CSV permanentes NÃO serão apagados."):
            self.log_text.delete(1.0, tk.END)
            self.log_message("🗑️ Visualização de logs limpa (arquivos CSV preservados).")
    
    def refresh_logs(self):
        """Atualiza a visualização com os logs do dia atual"""
        try:
            current_date = datetime.now().strftime('%Y-%m-%d')
            log_filename = f'logs/network_log_{current_date}.csv'
            
            if os.path.exists(log_filename):
                self.log_text.delete(1.0, tk.END)
                with open(log_filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Mostra últimas 1000 linhas para não sobrecarregar
                    lines = content.split('\n')
                    if len(lines) > 1000:
                        self.log_text.insert(tk.END, f"[Mostrando últimas 1000 linhas de {len(lines)} total]\n\n")
                        self.log_text.insert(tk.END, '\n'.join(lines[-1000:]))
                    else:
                        self.log_text.insert(tk.END, content)
            else:
                self.log_text.delete(1.0, tk.END)
                self.log_text.insert(tk.END, "Nenhum log encontrado para hoje.\n")
            
            self.update_log_info()
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao atualizar logs: {e}")
    
    def consolidate_all_logs(self):
        """Consolida todos os arquivos de log diários em um único arquivo"""
        try:
            success, message = self.monitor.consolidate_logs()
            if success:
                messagebox.showinfo("Sucesso", f"✅ {message}\n\nArquivo: network_log_CONSOLIDATED.csv")
            else:
                messagebox.showwarning("Aviso", message)
            self.update_log_info()
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao consolidar logs: {e}")
    
    def open_logs_folder(self):
        """Abre a pasta contendo os arquivos de log"""
        try:
            logs_path = os.path.join(os.getcwd(), 'logs')
            if not os.path.exists(logs_path):
                os.makedirs(logs_path)
            os.startfile(logs_path)
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao abrir pasta: {e}")
    
    def update_log_info(self):
        """Atualiza informações sobre os arquivos de log"""
        try:
            log_files = self.monitor.get_all_log_files()
            total_size = sum(os.path.getsize(f) for f in log_files if os.path.exists(f))
            size_mb = total_size / (1024 * 1024)
            
            info_text = f"📦 {len(log_files)} arquivos de log | 💾 {size_mb:.2f} MB total"
            if log_files:
                oldest = log_files[-1].replace('network_log_', '').replace('.csv', '')
                newest = log_files[0].replace('network_log_', '').replace('.csv', '')
                info_text += f" | 📅 {oldest} até {newest}"
            
            self.log_info_label.config(text=info_text)
        except Exception as e:
            self.log_info_label.config(text=f"Erro ao carregar info: {e}")
    
    def save_settings(self):
        try:
            self.monitor.alert_threshold = float(self.alert_threshold_spin.get())
            self.monitor.packet_loss_threshold = float(self.packet_loss_spin.get())
            self.monitor.anomaly_min_consecutive_normal = int(self.anomaly_buffer_spin.get())
            self.monitor.anomaly_deviation_multiplier = float(self.anomaly_deviation_spin.get())
            self.monitor.anomaly_min_pings = int(self.anomaly_min_pings_spin.get())
            self.monitor.enable_sound_alerts = self.sound_alert_var.get()
            self.monitor.enable_alerts = self.visual_alert_var.get()
            
            self.monitor.save_config()
            messagebox.showinfo("Sucesso", "Configurações salvas com sucesso!\n\n"
                              f"Detecção híbrida:\n"
                              f"• Threshold fixo: {self.monitor.alert_threshold}ms\n"
                              f"• Desvio estatístico: {self.monitor.anomaly_deviation_multiplier}x\n"
                              f"• Mínimo de pings: {self.monitor.anomaly_min_pings}")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao salvar configurações: {e}")
    
    def restore_defaults(self):
        if messagebox.askyesno("Confirmar", "Deseja restaurar as configurações padrão?"):
            self.alert_threshold_spin.set(100)
            self.packet_loss_spin.set(5)
            self.anomaly_buffer_spin.set(10)
            self.anomaly_deviation_spin.set(2.5)
            self.anomaly_min_pings_spin.set(5)
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
    
    def create_wifi_tab(self):
        """Aba para testar múltiplas redes WiFi automaticamente"""
        import re
        
        # Frame de controle
        control_frame = ttk.LabelFrame(self.tab_wifi, text='🔍 Escaneamento de Redes', padding=10)
        control_frame.pack(fill='x', padx=10, pady=5)
        
        # Linha 1: Botões de ação
        button_row1 = ttk.Frame(control_frame)
        button_row1.pack(fill='x', pady=2)
        
        ttk.Button(button_row1, text='📡 Escanear (Rápido)', 
                  command=self.scan_wifi_networks, style='Success.TButton').pack(side='left', padx=5)
        ttk.Button(button_row1, text='🔍 Escanear (Desconectar)', 
                  command=self.scan_wifi_disconnected, style='Success.TButton').pack(side='left', padx=5)
        ttk.Button(button_row1, text='🧪 Testar Redes Selecionadas', 
                  command=self.test_selected_networks, style='Success.TButton').pack(side='left', padx=5)
        ttk.Button(button_row1, text='⏹️ Parar Testes', 
                  command=self.stop_wifi_tests, style='Danger.TButton').pack(side='left', padx=5)
        ttk.Button(button_row1, text='🗑️ Limpar Cache WiFi', 
                  command=self.clear_wifi_cache, style='Danger.TButton').pack(side='left', padx=5)
        
        # Linha 2: Info da rede conectada
        self.current_wifi_label = ttk.Label(control_frame, text='📶 Conectado: Detectando...', 
                                            font=('Segoe UI', 9, 'bold'), foreground='#4ec9b0')
        self.current_wifi_label.pack(pady=5)
        
        # Atualiza rede atual
        self.update_current_wifi_display()
        
        # Config de teste
        config_frame = ttk.LabelFrame(self.tab_wifi, text='⚙️ Configuração de Teste', padding=10)
        config_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(config_frame, text='Duração por rede (minutos):').grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.wifi_test_duration = ttk.Spinbox(config_frame, from_=1, to=30, increment=1, width=10)
        self.wifi_test_duration.set(5)
        self.wifi_test_duration.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(config_frame, text='Limiar de anomalia (ms):').grid(row=0, column=2, padx=5, pady=5, sticky='w')
        self.wifi_anomaly_threshold = ttk.Spinbox(config_frame, from_=50, to=500, increment=10, width=10)
        self.wifi_anomaly_threshold.set(100)
        self.wifi_anomaly_threshold.grid(row=0, column=3, padx=5, pady=5)
        
        # Lista de redes
        networks_frame = ttk.LabelFrame(self.tab_wifi, text='📋 Redes WiFi Disponíveis (Selecione múltiplas)', padding=10)
        networks_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Scrollbar + Listbox
        scroll = ttk.Scrollbar(networks_frame, orient='vertical')
        self.wifi_listbox = tk.Listbox(networks_frame, selectmode='multiple', 
                                       yscrollcommand=scroll.set,
                                       bg='#1e1e1e', fg='#ffffff', 
                                       font=('Consolas', 10), height=10)
        scroll.config(command=self.wifi_listbox.yview)
        scroll.pack(side='right', fill='y')
        self.wifi_listbox.pack(side='left', fill='both', expand=True)
        
        # Log de status
        log_frame = ttk.LabelFrame(self.tab_wifi, text='📊 Status dos Testes', padding=10)
        log_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.wifi_log = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=15,
                                                   bg='#1e1e1e', fg='#ffffff',
                                                   font=('Consolas', 9))
        self.wifi_log.pack(fill='both', expand=True)
        
        # Variáveis de controle
        self.available_wifi_networks = []
        self.wifi_testing = False
        self.wifi_test_thread = None
        self.wifi_passwords = {}  # Cache de senhas
        self.wifi_passwords_file = 'wifi_passwords.enc'
        
        # Carrega senhas salvas
        self.load_wifi_passwords()
        
        self.wifi_log_message("✅ Testador Multi-Redes WiFi iniciado")
        self.wifi_log_message("ℹ️ Clique em 'Escanear Redes WiFi' para começar")
        self.wifi_log_message("⚠️ ATENÇÃO: Execute este programa como ADMINISTRADOR para escanear redes")
    
    def wifi_log_message(self, message):
        """Adiciona mensagem ao log WiFi"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.wifi_log.insert(tk.END, f"[{timestamp}] {message}\n")
        self.wifi_log.see(tk.END)
        self.root.update_idletasks()
    
    def update_current_wifi_display(self):
        """Atualiza display da rede WiFi conectada"""
        try:
            current = self.get_current_wifi_ssid()
            if current:
                self.current_wifi_label.config(text=f'📶 Conectado: {current}')
            else:
                self.current_wifi_label.config(text='📶 Desconectado', foreground='#f48771')
        except:
            self.current_wifi_label.config(text='📶 Status desconhecido')
    
    def load_wifi_passwords(self):
        """Carrega senhas WiFi salvas (criptografia simples)"""
        try:
            if os.path.exists(self.wifi_passwords_file):
                with open(self.wifi_passwords_file, 'r') as f:
                    encrypted = f.read()
                    # Descriptografa (base64 simples - não é seguro, mas melhor que texto puro)
                    decrypted = base64.b64decode(encrypted).decode('utf-8')
                    self.wifi_passwords = json.loads(decrypted)
                    self.wifi_log_message(f"🔐 {len(self.wifi_passwords)} senha(s) carregada(s)")
        except Exception as e:
            self.wifi_passwords = {}
            print(f"Erro ao carregar senhas: {e}")
    
    def save_wifi_passwords(self):
        """Salva senhas WiFi (criptografia simples)"""
        try:
            # Criptografa (base64 simples)
            json_data = json.dumps(self.wifi_passwords)
            encrypted = base64.b64encode(json_data.encode('utf-8')).decode('utf-8')
            with open(self.wifi_passwords_file, 'w') as f:
                f.write(encrypted)
        except Exception as e:
            print(f"Erro ao salvar senhas: {e}")
    
    def get_current_wifi_ssid(self):
        """Retorna o SSID da rede WiFi atualmente conectada"""
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'interfaces'],
                capture_output=True,
                text=True,
                encoding='cp850',
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            for line in result.stdout.split('\n'):
                if 'SSID' in line and ':' in line and 'BSSID' not in line:
                    ssid = line.split(':', 1)[1].strip()
                    if ssid:
                        return ssid
            return None
        except Exception as e:
            print(f"Erro ao obter SSID atual: {e}")
            return None
    
    def scan_wifi_networks(self):
        """Escaneia redes WiFi disponíveis no Windows COM INTERFACE ESPECÍFICA"""
        self.wifi_log_message("🔍 Escaneando redes WiFi...")
        self.wifi_log_message("⏳ Detectando interface WiFi e atualizando lista...")
        self.wifi_listbox.delete(0, tk.END)
        
        def scan_thread():
            try:
                # PASSO 1: Detecta nome da interface WiFi
                self.wifi_log_message("   └─ Detectando interface WiFi...")
                interface_result = subprocess.run(
                    ['netsh', 'wlan', 'show', 'interfaces'],
                    capture_output=True,
                    text=True,
                    encoding='cp850',
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                # Extrai nome da interface
                wifi_interface = "Wi-Fi"  # Padrão
                for line in interface_result.stdout.split('\n'):
                    if 'Nome' in line and ':' in line:
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            wifi_interface = parts[1].strip()
                            break
                
                self.wifi_log_message(f"   └─ ✓ Interface encontrada: '{wifi_interface}'")
                
                # PASSO 2: Força múltiplos scans COM INTERFACE ESPECÍFICA
                self.wifi_log_message(f"   └─ Escaneando redes na interface '{wifi_interface}'...")
                for i in range(5):
                    subprocess.run(
                        ['netsh', 'wlan', 'show', 'networks', f'interface={wifi_interface}'],
                        capture_output=True,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    time.sleep(1)
                    if i < 4:
                        self.root.after(0, lambda idx=i: self.wifi_log_message(f"      └─ Tentativa {idx+2}/5..."))
                
                self.root.after(0, lambda: self.wifi_log_message("   └─ Processando resultados..."))
                
                # PASSO 3: Pega lista completa COM INTERFACE ESPECÍFICA
                result = subprocess.run(
                    ['netsh', 'wlan', 'show', 'networks', f'interface={wifi_interface}', 'mode=Bssid'],
                    capture_output=True,
                    text=True,
                    encoding='cp850',
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                # Salva interface para usar em conexões posteriores
                self.detected_wifi_interface = wifi_interface
                
                import re
                networks = []
                lines = result.stdout.split('\n')
                
                i = 0
                while i < len(lines):
                    line = lines[i]
                    
                    # Procura por SSID (não BSSID)
                    if 'SSID' in line and 'BSSID' not in line and ':' in line:
                        # Extrai SSID
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            ssid = parts[1].strip()
                            
                            # Se tiver número "SSID 2 : Nome", remove
                            if ssid.startswith('SSID '):
                                ssid_parts = ssid.split(':', 1)
                                if len(ssid_parts) > 1:
                                    ssid = ssid_parts[1].strip()
                            
                            if ssid and ssid != '':
                                # Procura sinal nas próximas 10 linhas
                                signal = "?"
                                for j in range(i+1, min(i+10, len(lines))):
                                    if 'Sinal' in lines[j] or 'Signal' in lines[j]:
                                        signal_match = re.search(r'(\d+)%', lines[j])
                                        if signal_match:
                                            signal = signal_match.group(1) + "%"
                                            break
                                
                                # Adiciona sem duplicatas
                                if ssid not in [net[0] for net in networks]:
                                    networks.append((ssid, signal))
                                    self.wifi_log_message(f"  └─ Encontrada: {ssid} ({signal})")
                    
                    i += 1
                
                self.available_wifi_networks = networks
                
                # Atualiza interface
                def update_ui():
                    if networks:
                        for ssid, signal in networks:
                            self.wifi_listbox.insert(tk.END, f"{ssid} ({signal})")
                        self.wifi_log_message(f"✅ {len(networks)} rede(s) encontrada(s)")
                    else:
                        self.wifi_log_message("❌ Nenhuma rede encontrada")
                        self.wifi_log_message("⚠️ Verifique se está executando como ADMINISTRADOR")
                        self.wifi_log_message("⚠️ Verifique se o WiFi está ativado")
                
                self.root.after(0, update_ui)
                
            except Exception as e:
                self.root.after(0, lambda: self.wifi_log_message(f"❌ Erro: {e}"))
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def scan_wifi_disconnected(self):
        """Desconecta temporariamente e escaneia TODAS as redes"""
        self.wifi_log_message("🔍 Escaneamento PROFUNDO (Desconecta temporariamente)...")
        self.wifi_log_message("⚠️ Você será DESCONECTADO por ~10 segundos!")
        self.wifi_listbox.delete(0, tk.END)
        
        def scan_thread():
            try:
                # Salva rede atual para reconectar depois
                current_network = self.get_current_wifi_ssid()
                self.wifi_log_message(f"   └─ Rede atual: '{current_network}'")
                
                # Detecta interface
                interface_result = subprocess.run(
                    ['netsh', 'wlan', 'show', 'interfaces'],
                    capture_output=True,
                    text=True,
                    encoding='cp850',
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                wifi_interface = "Wi-Fi"
                for line in interface_result.stdout.split('\n'):
                    if 'Nome' in line and ':' in line:
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            wifi_interface = parts[1].strip()
                            break
                
                self.wifi_log_message(f"   └─ Interface: '{wifi_interface}'")
                
                # DESCONECTA para forçar scan completo
                self.wifi_log_message("   └─ 🔌 Desconectando WiFi...")
                subprocess.run(
                    ['netsh', 'wlan', 'disconnect', f'interface={wifi_interface}'],
                    capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                time.sleep(2)
                
                # Força 10 scans agressivos (sem conexão, pega tudo)
                self.wifi_log_message("   └─ 📡 Escaneando TODAS as redes disponíveis...")
                for i in range(10):
                    subprocess.run(
                        ['netsh', 'wlan', 'show', 'networks', f'interface={wifi_interface}', 'mode=Bssid'],
                        capture_output=True,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    time.sleep(0.5)
                    if (i + 1) % 3 == 0:
                        self.root.after(0, lambda idx=i: self.wifi_log_message(f"      └─ Scan {idx+1}/10..."))
                
                # Pega resultados
                self.root.after(0, lambda: self.wifi_log_message("   └─ Processando resultados..."))
                result = subprocess.run(
                    ['netsh', 'wlan', 'show', 'networks', f'interface={wifi_interface}', 'mode=Bssid'],
                    capture_output=True,
                    text=True,
                    encoding='cp850',
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                # Salva interface detectada
                self.detected_wifi_interface = wifi_interface
                
                # Processa redes
                import re
                networks = []
                lines = result.stdout.split('\n')
                
                i = 0
                while i < len(lines):
                    line = lines[i]
                    
                    if 'SSID' in line and 'BSSID' not in line and ':' in line:
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            ssid = parts[1].strip()
                            
                            if ssid.startswith('SSID '):
                                ssid_parts = ssid.split(':', 1)
                                if len(ssid_parts) > 1:
                                    ssid = ssid_parts[1].strip()
                            
                            if ssid and ssid != '':
                                signal = "?"
                                for j in range(i+1, min(i+10, len(lines))):
                                    if 'Sinal' in lines[j] or 'Signal' in lines[j]:
                                        signal_match = re.search(r'(\d+)%', lines[j])
                                        if signal_match:
                                            signal = signal_match.group(1) + "%"
                                            break
                                
                                if ssid not in [net[0] for net in networks]:
                                    networks.append((ssid, signal))
                                    self.wifi_log_message(f"  └─ Encontrada: {ssid} ({signal})")
                    
                    i += 1
                
                self.available_wifi_networks = networks
                
                # Atualiza UI
                def update_ui():
                    if networks:
                        for ssid, signal in networks:
                            self.wifi_listbox.insert(tk.END, f"{ssid} ({signal})")
                        self.wifi_log_message(f"✅ {len(networks)} rede(s) encontrada(s)")
                    else:
                        self.wifi_log_message("❌ Nenhuma rede encontrada")
                    
                    # Reconecta na rede original se possível
                    if current_network and current_network in [n[0] for n in networks]:
                        self.wifi_log_message(f"   └─ 🔄 Reconectando em '{current_network}'...")
                        if current_network in self.wifi_passwords:
                            password = self.wifi_passwords[current_network]
                            threading.Thread(
                                target=lambda: self.connect_to_wifi(current_network, password),
                                daemon=True
                            ).start()
                        else:
                            self.wifi_log_message(f"   └─ ⚠️ Senha de '{current_network}' não salva - reconecte manualmente")
                    
                    self.update_current_wifi_display()
                
                self.root.after(0, update_ui)
                
            except Exception as e:
                self.root.after(0, lambda: self.wifi_log_message(f"❌ Erro: {e}"))
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def test_selected_networks(self):
        """Testa as redes WiFi selecionadas sequencialmente"""
        selected_indices = self.wifi_listbox.curselection()
        
        if not selected_indices:
            messagebox.showwarning("Aviso", "Selecione pelo menos uma rede para testar!")
            return
        
        # Pega redes selecionadas
        selected_networks = [self.available_wifi_networks[i] for i in selected_indices]
        
        # Pede senhas (usa cache se disponível)
        network_credentials = {}
        for ssid, signal in selected_networks:
            # Tenta usar senha salva
            if ssid in self.wifi_passwords:
                use_saved = messagebox.askyesno(
                    "Senha Salva",
                    f"Usar senha salva para:\n{ssid}?"
                )
                if use_saved:
                    network_credentials[ssid] = self.wifi_passwords[ssid]
                    continue
            
            # Pede senha nova
            password = tk.simpledialog.askstring(
                f"Senha WiFi",
                f"Digite a senha para a rede:\n{ssid}",
                show='*'
            )
            if password is None:  # Usuário cancelou
                return
            network_credentials[ssid] = password
            
            # Pergunta se quer salvar
            if messagebox.askyesno("Salvar Senha", f"Salvar senha de '{ssid}' para próxima vez?"):
                self.wifi_passwords[ssid] = password
                self.save_wifi_passwords()
                self.wifi_log_message(f"🔐 Senha de '{ssid}' salva")
        
        # Confirma
        if not messagebox.askyesno("Confirmar", 
                                   f"Testar {len(selected_networks)} rede(s) em LOOP CONTÍNUO?\n\n"
                                   f"Duração: {self.wifi_test_duration.get()} min por rede\n"
                                   f"Modo: Alternância infinita entre as redes\n\n"
                                   f"⚠️ O WiFi será alternado automaticamente!\n"
                                   f"⚠️ Use 'Parar Testes' para interromper"):
            return
        
        # Para monitoramento atual se estiver rodando
        if self.monitor.monitoring:
            self.stop_monitoring()
            time.sleep(1)
        
        # Inicia thread de teste
        self.wifi_testing = True
        self.wifi_test_thread = threading.Thread(
            target=self.run_wifi_tests_loop,
            args=(selected_networks, network_credentials),
            daemon=True
        )
        self.wifi_test_thread.start()
    
    def clear_wifi_cache(self):
        """Limpa TODOS os perfis WiFi salvos (resolve conflitos de senha)"""
        if not messagebox.askyesno("⚠️ Confirmar Limpeza", 
                                   "Deseja APAGAR todos os perfis WiFi salvos?\n\n"
                                   "Isso irá:\n"
                                   "✓ Resolver conflitos de senha antiga\n"
                                   "✓ Limpar cache de credenciais\n"
                                   "✓ Forçar reconexão limpa\n\n"
                                   "⚠️ Você precisará inserir senhas novamente!"):
            return
        
        try:
            self.wifi_log_message("\n" + "="*60)
            self.wifi_log_message("🗑️ LIMPANDO CACHE DE PERFIS WiFi")
            self.wifi_log_message("="*60)
            
            # Lista todos os perfis
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'profiles'],
                capture_output=True,
                text=True,
                encoding='cp850',
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            profiles_deleted = 0
            for line in result.stdout.split('\n'):
                if 'Perfil de Todos' in line or 'All User Profile' in line:
                    # Extrai nome do perfil
                    parts = line.split(':')
                    if len(parts) > 1:
                        profile_name = parts[1].strip()
                        
                        # Deleta perfil
                        delete_result = subprocess.run(
                            ['netsh', 'wlan', 'delete', 'profile', f'name={profile_name}'],
                            capture_output=True,
                            creationflags=subprocess.CREATE_NO_WINDOW
                        )
                        
                        if delete_result.returncode == 0:
                            self.wifi_log_message(f"   ✓ Removido: {profile_name}")
                            profiles_deleted += 1
                        else:
                            self.wifi_log_message(f"   ✗ Erro ao remover: {profile_name}")
            
            self.wifi_log_message(f"\n✅ Limpeza concluída: {profiles_deleted} perfil(is) removido(s)")
            self.wifi_log_message(f"💡 Agora você pode testar as redes com senhas limpas!")
            
            messagebox.showinfo("Sucesso", 
                              f"Cache WiFi limpo!\n\n"
                              f"{profiles_deleted} perfil(is) removido(s)\n\n"
                              f"Agora reconecte usando as senhas corretas.")
            
        except Exception as e:
            self.wifi_log_message(f"❌ Erro ao limpar cache: {e}")
            messagebox.showerror("Erro", f"Erro ao limpar cache WiFi:\n{e}")
    
    def run_wifi_tests_loop(self, networks, credentials):
        """Executa testes em múltiplas redes em LOOP INFINITO alternando entre elas"""
        try:
            duration_minutes = int(self.wifi_test_duration.get())
            anomaly_threshold = int(self.wifi_anomaly_threshold.get())
            
            # Configura monitor principal
            self.monitor.anomaly_threshold = anomaly_threshold
            self.monitor.enable_sound_alerts = True
            self.monitor.enable_alerts = True
            
            cycle = 1
            
            # LOOP INFINITO
            while self.wifi_testing:
                self.wifi_log_message(f"\n{'='*60}")
                self.wifi_log_message(f"🔄 CICLO #{cycle} - Testando {len(networks)} rede(s)")
                self.wifi_log_message(f"{'='*60}")
                
                for ssid, signal in networks:
                    if not self.wifi_testing:
                        self.wifi_log_message("⏹️ Testes interrompidos pelo usuário")
                        return
                    
                    self.wifi_log_message(f"\n📡 TESTANDO: {ssid} ({signal}) - Ciclo {cycle}")
                    
                    # Conecta à rede
                    connection_result = self.connect_to_wifi(ssid, credentials[ssid])
                    if not connection_result:
                        self.wifi_log_message(f"❌ Falha ao conectar em {ssid} - PULANDO para próxima rede")
                        self.wifi_log_message(f"   └─ Motivo: Senha incorreta ou rede inacessível")
                        time.sleep(2)  # Pausa breve antes de tentar próxima
                        continue
                    
                    # Espera estabilizar e VERIFICA se conectou na rede correta
                    self.wifi_log_message("⏳ Aguardando conexão estabilizar...")
                    time.sleep(5)
                    
                    # VALIDAÇÃO: Verifica se está na rede certa
                    current_ssid = self.get_current_wifi_ssid()
                    if current_ssid != ssid:
                        self.wifi_log_message(f"⚠️ ERRO: Esperava '{ssid}' mas conectou em '{current_ssid}'")
                        self.wifi_log_message(f"⏩ Pulando teste (rede incorreta)")
                        continue
                    
                    self.wifi_log_message(f"✅ Conectado corretamente em: {current_ssid}")
                    
                    # Detecta gateway
                    gateway = self.monitor.get_default_gateway()
                    if not gateway:
                        gateway = '8.8.8.8'
                    self.wifi_log_message(f"🎯 Gateway: {gateway}")
                    
                    # Configura monitor principal para esta rede
                    self.monitor.current_server = gateway
                    
                    # Nome do arquivo: anomalias_NOME-DA-REDE_DATA.csv
                    current_date = datetime.now().strftime('%Y-%m-%d')
                    safe_ssid = ssid.replace(" ", "_").replace(":", "").replace("/", "_")
                    self.monitor.anomaly_file = f'logs/anomalias_{safe_ssid}_{current_date}.csv'
                    
                    # Reseta stats mas mantém histórico de anomalias
                    old_anomalies = self.monitor.detected_anomalies
                    self.monitor.reset_stats()
                    self.monitor.detected_anomalies = old_anomalies
                    
                    # Atualiza UI para mostrar qual rede está testando
                    def update_title():
                        self.root.title(f"Monitor de Rede - TESTANDO: {ssid}")
                    self.root.after(0, update_title)
                    
                    # INICIA MONITORAMENTO INTEGRADO
                    self.wifi_log_message(f"🚀 Monitorando por {duration_minutes} min com alertas e gráficos ativos...")
                    
                    # Usa a função normal de callback para integrar com interface
                    def wifi_callback(data):
                        # Chama callback normal para atualizar gráficos
                        self.on_monitor_data(data)
                        
                        # Log adicional no WiFi
                        if data.get('alert'):
                            self.wifi_log_message(f"⚠️ ALERTA: {data['alert']}")
                    
                    self.monitor.start_monitoring(wifi_callback)
                    
                    # Aguarda duração do teste
                    start_time = time.time()
                    end_time = start_time + (duration_minutes * 60)
                    
                    while time.time() < end_time and self.wifi_testing:
                        time.sleep(1)
                        
                        # Log de progresso a cada 30 segundos
                        elapsed = int(time.time() - start_time)
                        if elapsed % 30 == 0 and elapsed > 0:
                            remaining = int((end_time - time.time()) / 60)
                            avg = self.monitor.stats.get('avg_latency', 0)
                            pings = self.monitor.stats.get('total_pings', 0)
                            anomalies = len(self.monitor.detected_anomalies)
                            self.wifi_log_message(f"   ⏱️ {remaining}min restantes | {pings} pings | Média: {avg:.1f}ms | Anomalias: {anomalies}")
                    
                    # Para monitoramento
                    self.monitor.stop_monitoring()
                    
                    # Resumo
                    self.wifi_log_message(f"✅ Concluído: {ssid}")
                    self.wifi_log_message(f"   └─ Pings: {self.monitor.stats['total_pings']}")
                    self.wifi_log_message(f"   └─ Média: {self.monitor.stats.get('avg_latency', 0):.1f}ms")
                    self.wifi_log_message(f"   └─ Anomalias: {len(self.monitor.detected_anomalies)}")
                    
                    if not self.wifi_testing:
                        break
                
                cycle += 1
                
                if self.wifi_testing:
                    self.wifi_log_message(f"\n✅ Ciclo {cycle-1} completo! Reiniciando testes...")
            
        except Exception as e:
            self.wifi_log_message(f"❌ Erro nos testes: {e}")
            import traceback
            self.wifi_log_message(traceback.format_exc())
        finally:
            self.wifi_testing = False
            self.monitor.stop_monitoring()
            self.root.after(0, lambda: self.root.title("Monitor de Rede Professional - v2.9"))
    
    def connect_to_wifi(self, ssid, password):
        """Conecta a uma rede WiFi específica com VERIFICAÇÃO ROBUSTA"""
        try:
            self.wifi_log_message(f"🔌 Conectando a {ssid}...")
            
            # PASSO 1: Força escaneamento para atualizar lista do Windows
            self.wifi_log_message(f"   └─ Escaneando redes disponíveis...")
            for i in range(3):
                subprocess.run(
                    ['netsh', 'wlan', 'show', 'networks'],
                    capture_output=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                time.sleep(0.5)
            
            # PASSO 2: Verifica se rede está disponível
            result_scan = subprocess.run(
                ['netsh', 'wlan', 'show', 'networks'],
                capture_output=True,
                text=True,
                encoding='cp850',
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if ssid not in result_scan.stdout:
                self.wifi_log_message(f"❌ Rede '{ssid}' NÃO encontrada no alcance!")
                self.wifi_log_message(f"   └─ Verifique se a rede está ativa e próxima")
                return False
            
            self.wifi_log_message(f"   └─ ✓ Rede encontrada no alcance")
            
            # PASSO 3: Pega interface WiFi detectada
            wifi_interface = getattr(self, 'detected_wifi_interface', 'Wi-Fi')
            self.wifi_log_message(f"   └─ Usando interface: '{wifi_interface}'")
            
            # PASSO 4: ESQUECE a rede ANTES (limpa completamente)
            self.wifi_log_message(f"   └─ Esquecendo rede '{ssid}' completamente...")
            
            # Tenta esquecer da interface específica
            subprocess.run(
                ['netsh', 'wlan', 'delete', 'profile', f'name={ssid}', f'interface={wifi_interface}'],
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            # Tenta esquecer de TODAS as interfaces (força bruta)
            subprocess.run(
                ['netsh', 'wlan', 'delete', 'profile', f'name={ssid}'],
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            self.wifi_log_message(f"   └─ ✓ Perfil removido completamente")
            
            # PASSO 5: Desconecta de qualquer rede atual
            self.wifi_log_message(f"   └─ Desconectando de redes anteriores...")
            subprocess.run(
                ['netsh', 'wlan', 'disconnect', f'interface={wifi_interface}'],
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            time.sleep(3)  # Aguarda desconexão completa
            
            # PASSO 6: Cria perfil XML temporário com senha NOVA
            self.wifi_log_message(f"   └─ Criando perfil WiFi com senha NOVA...")
            profile_xml = f'''<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>manual</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{password}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>'''
            
            # Salva perfil temporário
            # Remove espaços e caracteres especiais do nome do arquivo
            safe_filename = ssid.replace(" ", "_").replace(":", "").replace("/", "_").replace("\\", "_")
            profile_file = f'wifi_profile_{safe_filename}.xml'
            with open(profile_file, 'w', encoding='utf-8') as f:
                f.write(profile_xml)
            
            # PASSO 7: Adiciona perfil NOVO na interface
            self.wifi_log_message(f"   └─ Adicionando perfil NOVO na interface '{wifi_interface}'...")
            result_add = subprocess.run(
                ['netsh', 'wlan', 'add', 'profile', f'filename={profile_file}', f'interface={wifi_interface}'],
                capture_output=True,
                text=True,
                encoding='cp850',
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            # Remove arquivo temporário
            os.remove(profile_file)
            
            # Debug: mostra resultado
            if result_add.returncode != 0:
                self.wifi_log_message(f"   └─ ⚠️ Aviso ao adicionar perfil: {result_add.stdout}")
            else:
                self.wifi_log_message(f"   └─ ✓ Perfil adicionado com sucesso")
            
            # Aguarda Windows processar o perfil
            time.sleep(2)
            
            # PASSO 8: Conecta à rede específica COM SSID E INTERFACE
            self.wifi_log_message(f"   └─ Iniciando conexão em '{wifi_interface}'...")
            result = subprocess.run(
                ['netsh', 'wlan', 'connect', f'name={ssid}', f'ssid={ssid}', f'interface={wifi_interface}'],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            # PASSO 9: Aguarda ATIVAMENTE até conexão completar (até 30s)
            self.wifi_log_message(f"   └─ Aguardando conexão WiFi estabilizar...")
            max_wait = 30  # segundos
            wait_interval = 2  # verifica a cada 2 segundos (mais estável)
            auth_failed = False
            
            for elapsed in range(0, max_wait, wait_interval):
                time.sleep(wait_interval)
                
                # Verifica se houve erro de autenticação
                status_result = subprocess.run(
                    ['netsh', 'wlan', 'show', 'interfaces'],
                    capture_output=True,
                    text=True,
                    encoding='cp850',
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                # Detecta falha de autenticação
                if 'desconectado' in status_result.stdout.lower() or 'disconnected' in status_result.stdout.lower():
                    # Verifica se já tentou conectar (não é desconexão inicial)
                    if elapsed > 4:
                        # Pode ser falha de senha
                        self.wifi_log_message(f"   └─ ⚠️ Desconectado após tentativa - possível senha incorreta")
                        time.sleep(2)
                        
                        # Tenta mais uma vez para confirmar
                        connected_ssid = self.get_current_wifi_ssid()
                        if connected_ssid != ssid:
                            self.wifi_log_message(f"❌ FALHA DE AUTENTICAÇÃO - Senha Incorreta")
                            self.wifi_log_message(f"   └─ A senha de '{ssid}' está INCORRETA")
                            self.wifi_log_message(f"   └─ Windows rejeitou a conexão")
                            self.wifi_log_message(f"")
                            self.wifi_log_message(f"💡 DICA: Se você tem certeza que a senha está correta:")
                            self.wifi_log_message(f"   1. Verifique se o roteador não mudou o tipo de segurança")
                            self.wifi_log_message(f"   2. Tente esquecer a rede manualmente no Windows")
                            self.wifi_log_message(f"   3. Reinicie o roteador se necessário")
                            return False
                
                connected_ssid = self.get_current_wifi_ssid()
                
                if connected_ssid == ssid:
                    self.wifi_log_message(f"   └─ ✓ Conectado após {elapsed+wait_interval}s")
                    # Aguarda mais 3s para garantir estabilidade completa
                    time.sleep(3)
                    
                    # Validação final tripla (3 verificações)
                    validations_ok = 0
                    for check_num in range(3):
                        time.sleep(1)
                        final_check = self.get_current_wifi_ssid()
                        if final_check == ssid:
                            validations_ok += 1
                        else:
                            self.wifi_log_message(f"   └─ ⚠️ Validação {check_num+1}/3: Ainda em '{final_check}'")
                    
                    if validations_ok == 3:
                        self.wifi_log_message(f"✅ CONFIRMADO: Conectado a '{ssid}' e estável (3/3 validações)")
                        # Testa ping para garantir que internet funciona
                        test_ping = self.monitor.ping_host('8.8.8.8')
                        if test_ping is None:
                            self.wifi_log_message(f"⚠️ AVISO: Conectado mas sem resposta de ping - verifique internet")
                        return True
                    else:
                        self.wifi_log_message(f"⚠️ Conexão instável: mudou de '{ssid}' para '{final_check}'")
                        return False
                
                # Feedback visual a cada 5 segundos
                if (elapsed + wait_interval) % 6 == 0:
                    self.wifi_log_message(f"   └─ Aguardando... ({elapsed+wait_interval}s/{max_wait}s)")
            
            # Timeout - não conectou em 30s
            connected_ssid = self.get_current_wifi_ssid()
            self.wifi_log_message(f"❌ TIMEOUT: Não conectou em {max_wait}s")
            
            # Verifica se é problema de senha
            if not connected_ssid:
                self.wifi_log_message(f"   └─ Possível SENHA INCORRETA para '{ssid}'")
                self.wifi_log_message(f"   └─ Windows tentou mas não conseguiu autenticar")
            else:
                self.wifi_log_message(f"   └─ Esperado: '{ssid}' | Atual: '{connected_ssid}'")
            
            return False
                
        except Exception as e:
            self.wifi_log_message(f"❌ Erro ao conectar: {e}")
            return False
    
    def stop_wifi_tests(self):
        """Para testes WiFi"""
        if not self.wifi_testing:
            messagebox.showinfo("Info", "Nenhum teste em execução")
            return
        
        self.wifi_testing = False
        self.monitor.stop_monitoring()
        self.wifi_log_message("⏹️ Parando testes...")
        self.wifi_log_message("⏳ Aguardando finalização...")


def main():
    root = tk.Tk()
    app = MonitorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
