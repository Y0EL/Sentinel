from celery import Celery
from celery.result import AsyncResult
from orchestrator import SentinelCrew
import asyncio
import json
from typing import Dict, Any
from celery_app import celery_app

@celery_app.task(bind=True)
def analyze_threat_case(self, target: str, image_path: str = None):
    """
    Celery task to analyze a single threat case using SentinelCrew
    """
    try:
        # Update task status
        self.update_state(
            state='PROGRESS',
            meta={'current': 0, 'total': 5, 'status': f'Starting analysis for {target}'}
        )
        
        # Run the analysis
        async def run_analysis():
            crew = SentinelCrew(target=target, image_path=image_path)
            
            def progress_callback(chunk):
                if chunk.get('type') == 'PROGRESS':
                    self.update_state(
                        state='PROGRESS',
                        meta={
                            'current': chunk.get('stage', 0),
                            'total': 5,
                            'status': f'Processing stage {chunk.get("stage", 0)}'
                        }
                    )
            
            result = await crew.run(on_chunk=progress_callback)
            return result
        
        # Run async function in sync context
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(run_analysis())
        loop.close()
        
        # Return successful result
        return {
            'status': 'SUCCESS',
            'result': result,
            'target': target
        }
        
    except Exception as exc:
        # Update task status with error
        self.update_state(
            state='FAILURE',
            meta={'error': str(exc), 'target': target}
        )
        raise exc

@celery_app.task
def analyze_multiple_threat_cases(threat_cases: list):
    """
    Celery task to analyze multiple threat cases in parallel
    """
    try:
        # Create group of parallel tasks
        from celery import group
        job_group = group(
            analyze_threat_case.s(tc.get('target'), tc.get('image_path'))
            for tc in threat_cases
        )
        
        # Execute group and wait for results
        result = job_group.apply_async()
        
        return {
            'status': 'SUCCESS',
            'group_id': result.id,
            'threat_cases': threat_cases
        }
        
    except Exception as exc:
        raise exc

@celery_app.task
def get_task_status(task_id: str):
    """
    Get status of a Celery task
    """
    try:
        result = AsyncResult(task_id, app=celery_app)
        
        return {
            'task_id': task_id,
            'state': result.state,
            'result': result.result if result.ready() else None,
            'info': result.info if result.state == 'PROGRESS' else None
        }
    except Exception as exc:
        return {
            'task_id': task_id,
            'error': str(exc)
        }
